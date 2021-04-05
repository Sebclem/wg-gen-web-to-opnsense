FROM python:3-alpine

WORKDIR /app
RUN mkdir -p /data

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

VOLUME [ "/data", "/wg_data" ]

CMD [ "python", "./wg-exporter.py" ]

LABEL org.opencontainers.image.source=https://github.com/Sebclem/wg-gen-web-to-opnsense/