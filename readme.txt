# prometheus

cd /media/sf_monitoring-stack
docker compose up -d prometheus

cd opt/monitoring-stack/prometheus/alertmanager/

#audit-api

cd /media/sf_monitoring-stack
docker compose build audit-api
docker compose up -d --force-recreate audit-api

#Все контейнеры

docker ps -a

#Нагрузка CPU 

timeout 2m bash -c 'while :; do :; done'

# Со второго сервера конфиги сохранить в эту папку и написать как устанавливать
#обновить докер файл под все наши зависимости