# Cloud Configuration Assessment Notes

## Using cloudmapper

```
cd /opt/cloudmapper/
source venv/bin/activate
```

## Examine configuration

```
cat config.json
cat ~/.aws/credentials
```

To use CloudMapper you need an AWS account with the SecurityAudit and job-function/ViewOnlyAccess privileges. After specifying the account ID in the config.json and AWS CLI credentials file you can collect the information needed for assessment using the command python3 cloudmapper.py collect --config config.json

```
python3 cloudmapper.py prepare --config config.json
```

## Network map

```
python3 cloudmapper.py webserver
```

Now go to http://localhost:8000 to view the visualization of the cloudmapper network
![image](https://github.com/user-attachments/assets/6c5da4fc-68b4-404e-a4e8-42fd865b7b0d)

Selecting the web server we can view the details to get things like public IP
![image](https://github.com/user-attachments/assets/c70c6b9c-2c2f-4aad-a6b0-f6345ace470d)


## Generate assessment report

```
python3 cloudmapper.py report --config config.json --accounts falsimentis
firefox web/account-data/report.html
```

open the scoutsuite report

```
firefox /home/sec504/labs/scoutsuite-report/aws-912182608192.html
```

ScoutSuite JSON reports

```
cd ~/labs/scoutsuite-report/scoutsuite-results
head -c 40 scoutsuite_results_aws-912182608192.js ; echo
tail -n +2 scoutsuite_results_aws-912182608192.js | jq '.' | more
tail -n +2 scoutsuite_results_aws-912182608192.js | jq '.services.ec2.regions[].vpcs[].instances[] | .name, .Tags'
```
