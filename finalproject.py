#!/usr/bin/env p
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask.ext.httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

from sqlalchemy import Column, ForeignKey, Integer, String, Float, Boolean, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask import Flask, render_template, request, redirect, jsonify, url_for, current_app
from flask import session as login_session
import json 
import httplib2
import random, string
'''
for oauth import
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
'''
''' for rate limiting import:'''

from redis import Redis
redis = Redis()

import time
from functools import update_wrapper

Base = declarative_base()


######SENSITIVE INFORMATION  TODO MOVE OUT OF CODE #####

foursquare_client_id = 'SMQNYZFVCIOYIRAIXND2D5SYBLQUOPDB4HZTV13TT22AGACD'

foursquare_client_secret = 'IHBS4VBHYWJL53NLIY2HSVI5A1144GJ3MDTYYY1KLKTMC4BV'

google_api_key = 'AIzaSyBz7r2Kz6x7wO1zV9_O5Rcxmt8NahJ6kos'


app = Flask(__name__)

auth = HTTPBasicAuth()
''' Receiving the following when implementing oauth:

 File "finalproject.py", line 43, in <module>
    open('client_secrets.json', 'r').read())['web']['client_id']
IOError: [Errno 2] No such file or directory: 'client_secrets.json'

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


@auth.verify_password
def verify_password(usercred, password):
    #check for user credentials
    user = User.checkuser(usercred)
    if not user:
        #authenticate data
        user = session.query(User).filter_by(username=usercred).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')

@app.route('/oauth/<provider>', methods = ['POST'])
def login(provider):
    #STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        #STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
          
        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            
        # # Verify that the access token is used for the intended user.
        # gplus_id = credentials.id_token['sub']
        # if result['user_id'] != gplus_id:
        #     response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # # Verify that the access token is valid for this app.
        # if result['issued_to'] != CLIENT_ID:
        #     response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # stored_credentials = login_session.get('credentials')
        # stored_gplus_id = login_session.get('gplus_id')
        # if stored_credentials is not None and gplus_id == stored_gplus_id:
        #     response = make_response(json.dumps('Current user is already connected.'), 200)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response
        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        #STEP 3 - Find User or make a new one
        
        #Get user info
        h = httplib2.Http()
        userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)
      
        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']
        
        
     
        #see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username = name, picture = picture, email = email)
            session.add(user)
            session.commit()

        

        #STEP 4 - Make token
        token = user.generate_auth_token(600)

        

        #STEP 5 - Send back token to the client 
        return jsonify({'token': token.decode('ascii')})
        
        #return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'
'''
'''rate limiting code taken out of lecture notes week 6'''

class RateLimit(object):
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)

def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)

def on_over_limit(limit):
    return (jsonify({'data':'You hit the rate limit','error':'429'}),429)

def ratelimit(limit, per=300, send_x_headers=True,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return update_wrapper(rate_limited, f)
    return decorator





@app.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response

@app.route('/rate-limited')
@ratelimit(limit=300, per=30 * 1)
def index():
    return jsonify({'response':'This is a rate limited response'})

'''End of rate limiting code'''

@app.route('/newUsers', methods=['POST'])
#create a new user
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    #check for missing credentials
    if username is None or password is None:
        abort(400)  
    #store user in database once all credentials are inputted  
    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    #once user is created return username and user id
    return (jsonify({'username': user.username, 'id': user.id}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


#find user using users
@app.route('/findUsers/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/resource')
@auth.login_required
def get_resource():
    return jsonify({'Greeting': 'Hey %s!' % g.user.username})

def createUser(name, email, picture):
    user = User(username = name, picture = picture, email = email)
    session.add(user)
    session.commit()
    return user

def getUser(email):
    user = session.query(User).filter_by(email=email).first()
    return user
'''
Route by which user creates a request
it takes in two parameters the meal type and a preffered location
it also reqires that a user be logged in with accurat credentials to access this
'''
@app.route('/createRequest/<mealType>/<location>', methods = ['POST'])
@auth.login_required
def createRequest(mealType, location):
    user_id = g.user.id
    (latitude,longitude) = getGeocodeLocation(location)
    request = LunchRequest(location = location, latitude = latitude, longitude = longitude, user_id = user_id, mealType = mealType, filled = False)
    session.add(request)
    session.commit()
    #adds the user's request to the database
    return "Your request has been created successfully"




#User can view all requests here provided there are requests stored
#If no requests are present it informs the user that there are no pending requests
@app.route('/viewRequests')
@auth.login_required
def ViewOpenRequests():
    allRequests = session.query(LunchRequest).filter_by(filled=False).all()
    if allRequests:
        with app.app_context():
            return jsonify(allRequests = [i.serialize for i in allRequests])
    else:
        return "Sorry! You have no pending requests"

#This route searches for soecific requests and requires user login
@app.route('/requestFilter/<int:request_id>/')
@auth.login_required
#User can view a specific request here based on an inputted id provided the request is stored on the databses

def ViewRequestbyID(request_id):
    lunchrequest = session.query(LunchRequest).filter_by(id = request_id).one()
    return jsonify(lunchrequest = lunchrequest.serialize)






'''This route allows the user to create a proposal to another user using a specified lunch request number'''
@app.route('/createProposal/<int:propID>', methods = ['POST'])
@auth.login_required
def createProposal(propID):
    user_id = g.user.id
    lunchrequest = session.query(LunchRequest).filter_by(id = propID).one()
    proposal = Proposal(proposed_by = user_id, proposed_to=lunchrequest.user_id , LunchRequestID = propID, filled = False)
    session.add(proposal)
    session.commit()
    return "Proposal Successfully Created!"

'''This route allows the user to search for their pending proposals
the user is also informed if they have no pending proposals'''
@app.route("/pendingProposals")
@auth.login_required
def CheckForPendingRequest():
    user_id = g.user.id
    proposals = session.query(Proposal).filter_by(proposed_to = user_id).filter_by(filled=False).all()
    if proposals:
        return jsonify(proposals = [i.serialize for i in proposals])
    else:
        return "No pending proposals found"


#This route searches for soecific proposals and requires user login
@app.route('/proposalFilter/<int:proposal_id>/')
@auth.login_required
#User can view a specific proposal here based on an inputted id provided the request is stored on the databses

def ViewProposalbyID(proposal_id):
    prop = session.query(Proposal).filter_by(LunchRequestID = proposal_id).one()
    return jsonify(proposal = prop.serialize)



'''Here users can confirm a proposal to turn it into a date'''
@app.route("/confirmProposal/<int:proposal_id>", methods = ['POST'])
@auth.login_required
def makeDate(proposal_id):
    acceptedproposal = session.query(Proposal).filter_by(id = proposal_id).one()
    if acceptedproposal == None:
        return "This proposal can't be found"
    if acceptedproposal.filled == True:
        return "This proposal has already been filled" 
    if acceptedproposal.proposed_to != g.user.id:
        return "This proposal was not made to you. You are not authorized to fulfil this request"
    acceptedproposal.filled = True
    lunchrequest = session.query(LunchRequest).filter_by(id = acceptedproposal.LunchRequestID).one()
    lunchrequest.filled = True
    date = MakeADate(lunchrequest.id, acceptedproposal.proposed_to, acceptedproposal.proposed_by)
    session.add(acceptedproposal)
    session.add(lunchrequest)
    session.commit()
    return date
'''Here users can reject proposals'''
@app.route("/rejectProposal/<int:proposal_id>")
@auth.login_required
def rejProp(request_id):
    rejectedproposal = session.query(Proposal).filter_by(lunchrequest_id = request_id).one()
    session.delete(rejectedproposal)
    session.commit()
    return

#STEP 6  Check to see if you have any open dates
@app.route("/CheckDates")
@auth.login_required
def CheckForConfirmedDates():
    user_id = g.user.id
    dates = session.query(Date).filter_by(or_(user1 ==user_id,user2 == user_id)).all()
    if dates:
        return jsonify(dates= [d.serialize for d in dates]) 
    else:
        return "you currently have no open dates"

def ViewDateDetails(date_id):
    date = session.query(Date).filter_by(date_id = date_id).one()
    return jsonify(date.serialize)

'''This piece of code was take out of thhe lecture excercises week4/solution/FindARestaurant.py'''

def getGeocodeLocation(inputString):
    #Replace Spaces with '+' in URL
    locationString = inputString.replace(" ", "+")
    url = ('https://maps.googleapis.com/maps/api/geocode/json?address=%s&key=%s'% (locationString, google_api_key))
    h = httplib2.Http()
    result = json.loads(h.request(url,'GET')[1])
    #print response
    latitude = result['results'][0]['geometry']['location']['lat']
    longitude = result['results'][0]['geometry']['location']['lng']
    return (latitude,longitude)

#This function takes in a string representation of a location and cuisine type, geocodes the location, and then pass in the latitude and longitude coordinates to the Foursquare API
def findARestaurant(latitude, longitude, mealType):
    #Use foursquare API to find a nearby restaurant and return the results
    #https://api.foursquare.com/v2/venues/search?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&v=20130815&ll=40.7,74&query=sushi
    url = ('https://api.foursquare.com/v2/venues/search?client_id=%s&client_secret=%s&v=20130815&ll=%s,%s&query=%s' % (foursquare_client_id, foursquare_client_secret,latitude,longitude,mealType))
    h = httplib2.Http()
    result = json.loads(h.request(url,'GET')[1])


    #Grab the first restaurant
    restaurant = result['response']['venues'][0]
    venue_id = restaurant['id'] 
    restaurant_name = restaurant['name']
    restaurant_address = restaurant['location']['formattedAddress']
    address = ""
    for i in restaurant_address:
        address += i + " "
    restaurant_address = address
    #Get a  300x300 picture of the restaurant using the venue_id (you can change this by altering the 300x300 value in the URL or replacing it with 'orginal' to get the original picture
    url = ('https://api.foursquare.com/v2/venues/%s/photos?client_id=%s&v=20150603&client_secret=%s' % ((venue_id,foursquare_client_id,foursquare_client_secret)))
    result = json.loads(h.request(url,'GET')[1])
    #Grab the first image
    #if no image available, insert default image url
    if result['response']['photos']['items']:
        firstpic = result['response']['photos']['items'][0]
        prefix = firstpic['prefix']
        suffix = firstpic['suffix']
        imageURL = prefix + "300x300" + suffix
    else:
        imageURL = "http://pixabay.com/get/8926af5eb597ca51ca4c/1433440765/cheeseburger34314_1280.png?direct"

    restaurantInfo = [{'name':restaurant_name, 'address':restaurant_address, 'image':imageURL}]

    return restaurantInfo

#Calculate the midpoint between two users' locations
def CalculateMidpoint(user1lat,user1long, user2lat, user2long):
    latitude = (user1lat + user2lat) / 2
    longitude = (user1long + user2long) / 2
    return "%s, %s" %(latitude, longitude)

def MakeADate(lunchrequest_id,user1_id, user2_id):
    #Call findARestaurant to choose the venue
    #Make a date object and send a confirmation to both attendees
    lunchrequest = session.query(LunchRequest).filter_by(id = lunchrequest_id).one()
    restaurant = findARestaurant(lunchrequest.latitude, lunchrequest.longitude, lunchrequest.mealType)
    date = Date(user1 = user1_id, user2 = user2_id, restaurant = restaurant[0]['name'], restaurant_address = restaurant[0]['address'], restaurant_image = restaurant[0]['image'])
    session.add(date)
    session.commit()
    return jsonify(date=date.serialize)

@app.route('/GetUserInfo/<int:user_id>/JSON')
def GetUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return jsonify(user=user.serialize)






if __name__ == '__main__':
    '''
    Create a database to store data for use within the project
    This database would compose of four table structures as indicated in the ERD in the project description
    '''

#TABLE 1 to store User information
    class User(Base):
        __tablename__ = 'user'
        id = Column(Integer, primary_key=True)
        username = Column(String(32), index=True)
        password_hash = Column(String(64))
        email = Column(String)
        picture = Column(String)

        @property
        def serialize(self):
            #Method used to return data in a recognisable format
            return {
            'name' : self.name,
            'picture' : self.picture,
                }

        def hash_password(self, password):
            self.password_hash = pwd_context.encrypt(password)

        def verify_password(self, password):
            return pwd_context.verify(password, self.password_hash)

        def generate_auth_token(self, expiration=600):
            s = Serializer(app.secret_key, expires_in=expiration)
            return s.dumps({'id': self.id})

        @staticmethod
        def checkuser(token):
            s = Serializer(app.config['SECRET_KEY'])
            try:
                data = s.loads(token)
            except SignatureExpired:
                return None    # valid token, but expired
            except BadSignature:
                return None    # invalid token
            user = session.query(User).get(data['id'])
            return user
    


    

#TABLE 2 to store Requests information
    class LunchRequest(Base):
        __tablename__ = 'lunchrequest'
   
        id = Column(Integer, primary_key=True)
        mealType = Column(String(50), nullable = False)
        location = Column(String)
        latitude = Column(Float, nullable = False)
        longitude = Column(Float, nullable = False)
        user_id = Column(Integer, ForeignKey('user.id'))
        user = relationship(User)
        filled = Column(Boolean)

        @property
        def serialize(self):
            #Method used to return data in a recognisable format
            return {
               'mealType' : self.mealType,
               'location' : self.location,
               'latitude' : self.latitude,
               'longitude' : self.longitude,
               'id'  : self.id,
               'user_id'   : self.user_id
           }

#TABLE 3 for Proposal Information
    class Proposal(Base):
        __tablename__ = 'proposal'
        id = Column(Integer, primary_key=True)
        proposed_by = Column(Integer)
        proposed_to = Column(Integer)
        LunchRequestID = Column(Integer, ForeignKey('lunchrequest.id'))
        lunchrequest = relationship(LunchRequest)
        filled = Column(Boolean)
        @property
        def serialize(self):
            #Method used to return data in a recognisable format
            return {
               'proposed_by'         : self.proposed_by,
               'proposed_to' : self.proposed_to,
               'LunchRequestID' : self.LunchRequestID,
               'filled' : self.filled
           }


#TABLE 4 for Date Information
    class Date(Base):
        __tablename__ = 'date'
        id = Column(Integer, primary_key=True)
        user1 = Column(String, nullable = False)
        user2 = Column(String, nullable = False)
        restaurant = Column(String)
        restaurant_address = Column(String)
        restaurant_image = Column(String)
       

        @property
        def serialize(self):
            #Method used to return data in a recognisable format
            return {
               'user1' : self.user1,
               'user2' : self.user2,
               'restaurant' : self.restaurant,
               'restaurant_address' : self.restaurant_address,
               'restaurant_image' : self.restaurant_image
           }
     
    engine = create_engine('sqlite:///finalproj.db')
    Base.metadata.create_all(engine)
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    app.secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(debug=True) 
