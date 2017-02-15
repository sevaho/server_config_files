#security measures
add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com https://assets.zendesk.com https://connect.facebook.net; img-src 'self' https://ssl.google-analytics.com https://s-static.ak.facebook.com https://assets.zendesk.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://assets.zendesk.com; font-src 'self' https://themes.googleusercontent.com; frame-src https://assets.zendesk.com https://www.facebook.com https://s-static.ak.facebook.com https://tautt.zendesk.com; object-src 'none'";

server
{
  listen       80;
  server_name  example.com;

  #Use https over http anytime
  return       301 https://$server_name$request_uri;

}
server 
{
  error_page  404  /notfound.html;

  listen 443 ssl default_server deferred;
  
  ssl_certificate /etc/nginx/ssl/cert_chain.crt;
  ssl_certificate_key /etc/nginx/ssl/cert.key;  

  ssl_session_cache shared:SSL:50m;
  ssl_session_timeout 5m;
  ssl_dhparam /etc/nginx/ssl/dhparam.pem;
  ssl_prefer_server_ciphers on;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_ciphers <TODO>

  resolver 8.8.8.8;
  ssl_stapling on;
  ssl_trusted_certificate /etc/nginx/ssl/site.com.crt;

  add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";

  root </path/to/root>;
  
  gzip on;
  gzip_types text/plain image/jpeg image/png text/css text/javascript;

  error_log /data/sevaho.com/logs/error.log error;
  access_log /data/sevaho.com/logs/acces.log;

  client_max_body_size 10G; # set max upload size
  fastcgi_buffers 64 4K;

  location / {
    index index.html index.htm index.nginx-debian.html index.php;
  }

  server_name <site.com>;

  location ~ [^/].php(/|$) {
    fastcgi_split_path_info ^(.+?.php)(/.*)$;
    fastcgi_pass unix:/var/run/php5-fpm.sock;
    fastcgi_index index.php;
    include fastcgi_params;
  }
  # ownCloud blacklist
  location ~ ^/owncloud/(?:\.htaccess|data|config|db_structure\.xml|README) {
    deny all;
    error_page 403 = /owncloud/core/templates/403.php;
  }
  location /owncloud/ {
    error_page 403 = /owncloud/core/templates/403.php;
    error_page 404 = /owncloud/core/templates/404.php;

    rewrite ^/owncloud/caldav(.*)$ /remote.php/caldav$1 redirect;
    rewrite ^/owncloud/carddav(.*)$ /remote.php/carddav$1 redirect;
    rewrite ^/owncloud/webdav(.*)$ /remote.php/webdav$1 redirect;

    rewrite ^(/owncloud/core/doc[^\/]+/)$ $1/index.html;

    # The following rules are only needed with webfinger
    rewrite ^/owncloud/.well-known/host-meta /public.php?service=host-meta last;
    rewrite ^/owncloud/.well-known/host-meta.json /public.php?service=host-meta-json last;
    rewrite ^/owncloud/.well-known/carddav /remote.php/carddav/ redirect;
    rewrite ^/owncloud/.well-known/caldav /remote.php/caldav/ redirect;

    try_files $uri $uri/ index.php;
  }

  #REVERSE-PROXY NODE JS ON 5000
  location ~ ^/(client|socket\.io) {
    proxy_pass http://127.0.0.1:5000;
    roxy_set_header Host $host;
    proxy_set_header Origin http://$host; 
    proxy_http_version 1.1;
    proxy_cache_bypass $http_upgrade;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_connection;
  }

  #REVERSE-PROXY NETDATA 19999
  location ~ /netdata.* {
   auth_basic "Protected";
    auth_basic_user_file passwords;
    rewrite (/netdata)$ / break;
    rewrite /netdata/(.*) /$1 break;
    proxy_pass http://127.0.0.1:19999;
    proxy_redirect / /netdata/;
    proxy_set_header Host $host;
    proxy_set_header Origin http://$host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_connection;
  }
}
