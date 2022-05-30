FROM httpd
ARG KEYCLOAK_URI
ADD src /usr/local/apache2/htdocs/
RUN sed -i 's|!!KEYCLOAK_URI!!|'"$KEYCLOAK_URI"'|g' /usr/local/apache2/htdocs/index.html