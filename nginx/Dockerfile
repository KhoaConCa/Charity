FROM nginx:latest

COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /etc/nginx/html/index.html
COPY ./client/baodungkhoaphu.online.crt /etc/nginx/ssl/baodungkhoaphu.online.crt
COPY ./client/baodungkhoaphu.online.key /etc/nginx/ssl/baodungkhoaphu.online.key

EXPOSE 80 443