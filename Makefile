COUNTRY?=

build:
	wget -O ./modules/SigSci.py https://raw.githubusercontent.com/signalsciences/SigSciApiPy/master/SigSci.py
	wget -O ./data/GeoLite2-City.tar.gz http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
	cd ./data/ && tar -xzf GeoLite2-City.tar.gz
	rm ./data/GeoLite2-City.tar.gz
	mv ./data/GeoLite2-City_*/GeoLite2-City.mmdb ./data/
	virtualenv .env
	. .env/bin/activate && pip install --upgrade future requests geoip2

run:
	. .env/bin/activate && ./sigsci-country-block.py --country $(COUNTRY)

clean:
	find . -name "*.pyc" -type f -delete
	rm modules/SigSci.py
	rm -rf data/*
	echo "data directory" > data/readme.txt