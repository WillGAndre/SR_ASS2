Links:
	https://flask.palletsprojects.com/en/2.0.x/quickstart/
	https://auth0.com/blog/how-to-handle-jwt-in-python/
	https://www.freecodecamp.org/news/learn-data-structures-flask-api-python/
	https://nse.digital/pages/guides/web/authentication.html
	https://www.prplbx.com/resources/blog/broken-access-control/
				**---**
Docs:	
	To create db file, in python3 console, RUN:
	from server import db
	db.create_all()

				**---**
API:
	Create unsecure API with flask (python),
	this API could include a db with user info
	and blog posts info. 

	Create ACL for each user role: default, 		
	subscriber and admin (JWT). Simulate 			
	privilege escalation using these roles,				
	ex: default role has less clearence than		=>	Contrast how PoLP (access control policy)
	subscriber and admin, although due to some			would mitigate this issue.
	faulty design, there is a way to escalate
	a users privilege by changing roles. 
|
 \
  --> Add Authentication Authority that uses JWT tokens
      in an insecure manner. 


	Exploits:
        API Missconfig:
           Separate Id for blog that overrides user, allowing tampering in an insecure manner: DELETE, GET, PUT

		URL tampering which allows faulty requests with obsfucation.
   
        Privilege escalation: (defualt, subscriber, admin)
                \
                 --> JWT token: Change user access roles --> Faulty token: 
                                                               Body: (user roles, secret MD5)
                 --> IDOR
				 --> Bouncing between user roles, exploiting weak credentials.
				 	(default) --> (subscriber) --> (admin)
					 		  Weak			  Broken
						   credentials		  method

		Dirbuster / Spider: Hidden admin pages (or config files: robots.txt)

		CORS proxy:
			Using CORS proxy to allow requests from diff origins even if
			CORS is well configured.

			OR:
				Two implementations:
					--> CORS Missconfig ('Access-Control-Allow-Origin: *'): Communication between client and API.
					--> CORS well configured: Communication client and server, after auth between server and API.

    Solutions:
    	POLP with JWT tokens
    	API well configured

				**---**

Blog Posts for each user, this includes editing, delete
	\
	 ---> Privacy and Public posts

Profile page for each user (to add vulnerabilites) ---> Using cookies to save sessions 

Upload files/profile picture, based on user role ---> Useful for inserting malicious code	

				**---**
