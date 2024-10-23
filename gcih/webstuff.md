# Web stuff Notes

So this is going to be about 3 stuff put together Command Injection, Cross-Site Scripting and SQL injection. 
Just grouping these because man it was kinda short.

Identify the pages associated with the following functions:

- Feedback Submission
- Feedback Review
- Directory Services
- System Connectivity Checked
- Website Search Function
- Website Administrative Access Page

simple system input for a connectivity test page

- test with '-h' to see if you get help page info
    - '127.0.0.1 -h' or just '-h'
- try with '; ls'
    - '; ls'
- other things to try
    - '|| ls' or '&& ls'
