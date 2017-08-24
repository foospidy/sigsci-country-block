# sigsci-country-block
Signal Sciences Block Attacking IP Addresses by Country

# Usage

Export the following environment variables:

```
export SIGSCI_EMAIL=<api-account-email>
export SIGSCI_PASSWORD=<api-account-password>
export SIGSCI_CORP=<corp-name>
export SIGSCI_SITE=<site-name>
```

Use make to build and run (this will create a virtualenv to run in):

```
make build
make run country=<country-iso-code>
```

To run as deamon make sure you have the python dependancies installed, e.g. `pip install --upgrade future requests geoip2`

```
./sigsci-country-block.py --country <ccountry-iso-code> &
```