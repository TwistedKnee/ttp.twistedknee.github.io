# Cloud Bucket Discovery notes

review the aws credentials of your system

```
cat ~/.aws/credentials
```

### Make a bucket

```
aws s3 mb s3://mybucket
```

### push files to bucket

```
ps -ef > pslist.txt
aws s3 cp pslist.txt s3://mybucket2/
```

### list files from bucket

```
aws s3 ls s3://mybucket2
```

### Reviewing files of a public bucket

```
aws s3 ls s3://www.falsimentis.com
```

### Bypassing endpoint authentication 

in some cases browsers may block you from the files exposed, but the usage of aws may allow us to access this bucket and download it

```
aws s3 ls s3://www.falsimentis.com/protected/
aws s3 sync s3://www.falsimentis.com/protected/ protected/
```

### Bucket Discovery

using a tool to try to find buckets with a wordlists

```
bucket_finder.rb ~/labs/s3/shortlist.txt
bucket_finder.rb ~/labs/s3/bucketlist.txt | tee bucketlist1-output.txt
grep -v "does not exist" bucketlist1-output.txt
```

create a custom wordlists for this

```
head ~/labs/s3/permutations.txt
awk '{print "falsimentis-" $1}' ~/labs/s3/permutations.txt > bucketlist2.txt
bucket_finder.rb bucketlist2.txt | tee bucketlist2-output.txt
grep -v "does not exist" bucketlist2-output.txt
```

### Custom list with CeWL

```
/opt/cewl/cewl.rb -m 2 -w cewl-output.txt http://www.falsimentis.com
cat cewl-output.txt | tr [:upper:] [:lower:] > cewl-wordlist.txt
awk '{print "falsimentis-" $1}' cewl-wordlist.txt > bucketlist3.txt
bucket_finder.rb bucketlist3.txt | tee bucketlist3-output.txt
```
