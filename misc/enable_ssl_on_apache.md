openssl req -x509 -newkey rsa:2048 -keyout mykey.key -out mycert.pem -days 365 -nodes

sudo cp mycert.pem /etc/ssl/certs
sudo cp mykey.key /etc/ssl/private

sudo a2enmod ssl

sudo vim /etc/apache2/sites-available/default-ssl.conf
  #edit the sslcertificate and key line with the above location in /etc/ssl certs and private

cd /etc/apache2/sites-available

sudo a2ensite default-ssl.conf

sudo systemctl reload apache2

And you are done
