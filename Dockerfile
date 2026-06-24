FROM node:20.11.1-alpine3.19

WORKDIR /app

COPY package.json ./
COPY app.js ./
COPY template.zip ./

EXPOSE 3000

RUN apk add --no-cache curl bash unzip && \
    npm install && \
    chmod +x app.js && \
    unzip -q template.zip -d /tmp/tpl/ && \
    mkdir -p public && \
    if [ $(ls /tmp/tpl/ | wc -l) -eq 1 ] && [ -d "/tmp/tpl/$(ls /tmp/tpl/)" ]; then \
        mv /tmp/tpl/$(ls /tmp/tpl/)/* public/ ; \
    else \
        mv /tmp/tpl/* public/ ; \
    fi && \
    rm -rf /tmp/tpl/ template.zip

CMD ["npm", "start"]