# start the instance
docker run -d --rm --name decnet-mysql \
    -e MYSQL_ROOT_PASSWORD=root \
    -e MYSQL_DATABASE=decnet \
    -e MYSQL_USER=decnet \
    -e MYSQL_PASSWORD=decnet \
    -p 3307:3306 mysql:8

until docker exec decnet-mysql mysqladmin ping -h127.0.0.1 -uroot -proot --silent; do
    sleep 1
done

echo "MySQL up."

export DECNET_DB_TYPE=mysql
export DECNET_DB_URL='mysql+asyncmy://root:root@127.0.0.1:3307/decnet'

source .venv/bin/activate

sudo .venv/bin/decnet api
