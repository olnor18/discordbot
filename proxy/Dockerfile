FROM nginx:stable-alpine
COPY default.conf /etc/nginx/conf.d
EXPOSE 80 443
CMD ["/bin/sh", "-c", "exec nginx -g 'daemon off;';"]
#cmd ["/bin/sh", "-c", "ls -la /etc/ssl;"]
