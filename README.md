# Xades

### Apache Bench Notes

Use `POST-data.txt`
`Content-Type: application/x-www-form-urlencoded`

```
# post_loc.txt contains the json you want to post
# -p means to POST it
# -H adds an Auth header (could be Basic or Token)
# -T sets the Content-Type
# -c is concurrent clients
# -n is the number of requests to run in the test

test$ ab -p POST-data.txt -T application/x-www-form-urlencoded -c 2 -n 100 http://localhost:8080/signFromPath
```

Example:

```
❯ ab -p POST-data.txt -T application/x-www-form-urlencoded -c 2 -n 100 http://localhost:8080/signFromPath
This is ApacheBench, Version 2.3 <$Revision: 1826891 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking localhost (be patient)...
```