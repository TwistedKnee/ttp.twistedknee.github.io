# Cloud Scanning Notes

scanning with masscan

```
masscan -p 443 --rate 10000 -oL simcloud.txt 10.200.0.0/16
awk '/open/ {print $4}' simcloud.txt > simcloud-targets.txt
cat simcloud-targets.txt
tls-scan --port=443 --cacert=/opt/tls-scan/ca-bundle.crt -o simcloud-tlsinfo.json < simcloud-targets.txt
jq '.ip + " " + .certificateChain[].subjectCN' < simcloud-tlsinfo.json
```

creating eyewitness report

```
/opt/eyewitness/Python/EyeWitness.py --web -f simcloud-targets.txt --prepend-https
```

bonus

```
curl -k https://10.200.74.2/robots.txt
```

download and get metadata of these files

```
exiftool *.docx *.pdf | grep -i -E "author|editor|application|producer"
```
