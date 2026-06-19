FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples ./examples

RUN python -m pip install --no-cache-dir .

ENTRYPOINT ["auto-sec-bench"]
CMD ["assess", "--input", "examples/ecu_risks.json", "--json-out", "artifacts/assessment.json", "--html-out", "artifacts/assessment.html"]
