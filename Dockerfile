# nginx 1.31.8 - vulnerable HTTP/2 build (shipped with --with-http_v2_module)
FROM nginx:1.31.8-alpine

RUN mkdir -p /opt/lab/html

COPY conf/nginx.conf /etc/nginx/nginx.conf
COPY conf/cert.pem /opt/lab/cert.pem
COPY conf/key.pem /opt/lab/key.pem
COPY conf/big.bin /opt/lab/html/big.bin
COPY conf/index.html /opt/lab/html/index.html

EXPOSE 18443
WORKDIR /opt/lab/data

CMD ["nginx", "-g", "daemon off;"]
