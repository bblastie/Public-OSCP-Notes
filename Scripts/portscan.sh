

for port in  22 25 80 443 8080 8443; do
    (echo HELLO > /dev/tcp/172.16.1.5/$port && echo 'open - $port') 2> /dev/null
done