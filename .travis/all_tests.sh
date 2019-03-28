
python setup.py test -a "--cov=advocate --cov-config=.coveragerc"
python setup.py requests_test -l "../dev_packages/requests-${REQUESTS_VERSION}"
