FROM craftcms/nginx:8.2

ARG CRAFT_VERSION

USER root
RUN mkdir -p /app
WORKDIR /app
RUN wget "https://github.com/craftcms/cms/releases/download/${CRAFT_VERSION}/CraftCMS-${CRAFT_VERSION}.zip" -O CraftCMS.zip
RUN unzip -o CraftCMS.zip
COPY env /app/.env
RUN chown -R www-data.www-data /app
USER www-data
