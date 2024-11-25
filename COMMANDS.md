# Register a new user
## curl "http://127.0.0.1:5000/register?user=cory&pass=corypass"
### curl "http://172.30.0.12:5000/register?user=cory&pass=corypass"

# Login as that user
## curl "http://127.0.0.1:5000/login?user=cory&pass=corypass" 
### curl "http://172.30.0.12:5000/login?user=cory&pass=corypass"

# Deposit $
## curl --cookie "session=cory" "http://127.0.0.1:5000/manage?action=deposit&amount=100"
### curl --cookie "session=cory" "http://172.30.0.12:5000/manage?action=deposit&amount=100"

# Withdraw $
## curl --cookie "session=cory" "http://127.0.0.1:5000/manage?action=withdraw&amount=50"
### curl --cookie "session=cory" "http://172.30.0.12:5000/manage?action=withdraw&amount=500"

# Check $
## curl --cookie "session=cory" "http://127.0.0.1:5000/manage?action=balance"
### curl --cookie "session=cory" "http://172.30.0.12:5000/manage?action=balance"

# Logout user
## curl --cookie "session=cory" "http://127.0.0.1:5000/logout"
### curl --cookie "session=cory" "http://172.30.0.12:5000/logout"