NGINX_PATH=/home/simon/Downloads/nginx-1.16.1/

MODULE_PATH=$(pwd)/
CONFIG_ARGS=$(nginx -V 2>&1 | tail -n 1 | cut -c 21- | sed 's/--add-dynamic-module=.*//g')

CONFIG_ARGS="${CONFIG_ARGS} --add-dynamic-module=${MODULE_PATH}"

echo $CONFIG_ARGS

(
cd ${NGINX_PATH}
bash -c "./configure ${CONFIG_ARGS}"
make modules
)
