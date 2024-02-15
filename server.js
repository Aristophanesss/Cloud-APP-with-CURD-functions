/**
 * Author: Chen Xue
 * Date: 06-05-2023
 * Description: Portfolio Assignment for CS493 Cloud Application Development
 * Code Reference: https://canvas.oregonstate.edu/courses/1915173/pages/exploration-intermediate-rest-api-features-with-node-dot-js?module_item_id=23098401
 *                 https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise
 *                 https://stackoverflow.com/questions/39458201/understanding-javascript-promise-object 
 */

const express = require('express');
const app = express();

const { Datastore } = require('@google-cloud/datastore');
const bodyParser = require('body-parser');
const request = require('request');

const datastore = new Datastore();

const jwt = require('express-jwt');
const jwtTo = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');

const BOATS = "boats"; 
const LOADS = "loads";
const USERS = "users";

const router = express.Router();
const login = express.Router();

const CLIENT_ID = 'TrJQYFTdsAtQwbDpd1KChqUZDNqSaNpo';
const CLIENT_SECRET = 'nQy4hv7CjpHqA17_TyAJmQszLdnOKhXP5LWKM0s3RC6wplSx2j7adJgoNH47SNub';
const DOMAIN = 'dev-yil1qqc586j5hdkg.us.auth0.com';

app.use(bodyParser.json());

function fromDatastore(item) {
    item.id = item[Datastore.KEY].id;
    return item;
}

const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
  
    // Validate the audience and the issuer.
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256']
});

/* ------------- JWT Controller Function ------------- */
// Get the JWTs from Auth0
login.post('/', function(req, res){
    const username = req.body.username;
    const password = req.body.password;
    var options = { method: 'POST',
            url: `https://${DOMAIN}/oauth/token`,
            headers: { 'content-type': 'application/json' },
            body:
             { grant_type: 'password',
               username: username,
               password: password,
               client_id: CLIENT_ID,
               client_secret: CLIENT_SECRET },
            json: true };
    request(options, (error, response, body) => {
        if (error){
            res.status(500).json({ "Error": "Unknown error" });
        } else {
            // Check if the user exists in the datastore, if not add the user
            const q = datastore.createQuery(USERS).filter('username', '=', username);
            datastore.runQuery(q).then((entities) => {
                if (entities[0].length === 0) {
                    // Extract the sub claim from the ID token
                    const idToken = body.id_token;
                    const decodedToken = jwtTo.decode(idToken);
                    const userSub = decodedToken.sub;
          
                    // Set JWT's sub as the key for the new user
                    const new_user = { "username": username, "password": password, "sub": userSub };
                    const key = datastore.key(USERS);
                    datastore.save({ "key": key, "data": new_user });
                  }
            });

            // Return the JWTs
            res.send(body);
        }
    });
});
/* ------------- JWT Function End ------------- */

/* ------------- Begin Users Model Functions ------------- */
function get_users(req) {
    var q = datastore.createQuery(USERS)
    return datastore.runQuery(q).then((entities) => {
        return entities[0].map(fromDatastore);
    });
}
/* ------------- End Users Model Functions ------------- */

/* ------------- Begin Users Controller Functions ------------- */
// Get all users, no pagination, no JWT required
// Only shows those with sub
router.get('/users', function (req, res) {
    get_users(req)
        .then((users) => {
            res.status(200).json(users);
        });
});
/* ------------- End Users Controller Functions ------------- */

/* ------------- Begin Boats Model Functions ------------- */

// Post a new boat to the datastore
function post_boats(name, type, length, owner) {
    var key = datastore.key(BOATS);
    const new_boat = { "name": name, "type": type, "length": length, "loads": [], "owner": owner};
    return datastore.save({ "key": key, "data": new_boat }).then(() => { return key });
}

// Get all Boats for a specific user, with pagination 5 boats per page
function get_boats(req, owner) {
    const q = datastore.createQuery(BOATS).limit(5);
    const results = {};
    if (Object.keys(req.query).includes("cursor")) {
      q.start(req.query.cursor);
    }
    return datastore.runQuery(q).then((entities) => {
      results.boats = entities[0].map(fromDatastore).filter((item) => item.owner === owner);
      results.next = entities[1].moreResults !== Datastore.NO_MORE_RESULTS ? `${req.protocol}://${req.get("host")}${req.baseUrl}/boats?cursor=${entities[1].endCursor}` : null;
      return results;
    });
  }
  

// Get a single boat from the datastore
function get_single_boat(id) {
    const key = datastore.key([BOATS, parseInt(id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return entity;
        } else {
            return entity.map(fromDatastore);
        }
    });
}

// Update a boat in the datastore
function put_boats(id, name, type, length, loads, owner) {
    const key = datastore.key([BOATS, parseInt(id, 10)]);
    const boats = { "name": name, "type": type, "length": length, "loads": loads, "owner": owner };
    return datastore.save({ "key": key, "data": boats });
}

// Delete a boat from the datastore
function delete_boats(id) {
    const key = datastore.key([BOATS, parseInt(id, 10)]);
    // Check if the id is valid
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return entity;
        } else {
            return datastore.delete(key);
        }
    });
}

// Edit a boat, JWT required, loads cannot be updated
function update_boats(res, req) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') { 
        // JWT is provided
        checkJwt(req, res, (err) => {
          if (err) {
            // Invalid JWT
            res.status(405).json({ "Error": "Invalid JWT" });
          } else {
            // Valid JWT, retrieve the boat and check ownership
            get_single_boat(req.params.boat_id).then((boat) => {
              if (!boat[0]) {
                res.status(404).json({ "Error": "No boat with this boat_id exists" });
              } else if (boat[0].owner !== req.user.sub) {
                res.status(403).json({ "Error": "The boat does not belong to the authenticated user" });
              } else {
                // Update the boat
                if (req.body.name) {
                  boat[0].name = req.body.name;
                }
    
                if (req.body.type) {
                  boat[0].type = req.body.type;
                }
    
                if (req.body.length) {
                  boat[0].length = req.body.length;
                }
    
                // If loads are provided, return 406 status code
                if (req.body.loads && JSON.stringify(req.body.loads) !== JSON.stringify(boat[0].loads)) {
                  res.status(406).json({ "Error": "Loading/unloading needs to use other endpoints" });
                } else {
                  // If owner is provided, check if the new owner exists
                  if (req.body.owner && req.body.owner != boat[0].owner) {
                    const q = datastore.createQuery(USERS).filter('sub', '=', req.body.owner);
                    datastore.runQuery(q).then((entities) => {
                      if (entities[0].length === 0) {
                        res.status(403).json({ "Error": "The new owner does not exist" });
                      } else {
                        boat[0].owner = req.body.owner;
                        // Save the updated boat
                        put_boats(req.params.boat_id, boat[0].name, boat[0].type, boat[0].length, boat[0].loads, boat[0].owner)
                          .then(() => {
                            res.status(200).json({
                              "id": req.params.boat_id,
                              "name": boat[0].name,
                              "type": boat[0].type,
                              "length": boat[0].length,
                              "loads": boat[0].loads,
                              "owner": boat[0].owner,
                              "self": `https://xueche-cs493-final.uw.r.appspot.com/boats/${req.params.boat_id}`
                            });
                          })
                          .catch((error) => {
                            res.status(500).json({ "Error": "An error occurred while updating the boat" });
                          });
                      }
                    }).catch((error) => {
                      res.status(500).json({ "Error": "An error occurred while querying the new owner" });
                    });
                  } else {
                    // No owner change, save the boat
                    put_boats(req.params.boat_id, boat[0].name, boat[0].type, boat[0].length, boat[0].loads, boat[0].owner)
                      .then(() => {
                        res.status(200).json({
                          "id": req.params.boat_id,
                          "name": boat[0].name,
                          "type": boat[0].type,
                          "length": boat[0].length,
                          "loads": boat[0].loads,
                          "owner": boat[0].owner,
                          "self": `https://xueche-cs493-final.uw.r.appspot.com/boats/${req.params.boat_id}`
                        });
                      })
                      .catch((error) => {
                        res.status(500).json({ "Error": "An error occurred while updating the boat" });
                      });
                  }
                }
              }
            }).catch((error) => {
              res.status(500).json({ "Error": "An error occurred while retrieving the boat" });
            });
          }
        });
      }
}
/* ------------- End Boats Model Functions ------------- */

/* ------------- Begin Boats Functions ------------- */
// Add a new boat, requires JWT
router.post('/boats', checkJwt, function (req, res) {
    if(req.get('content-type') !== 'application/json'){
        res.status(406).json({ "Error": "Server only accepts application/json data" });
    } else if (!req.user || !req.user.sub){ // If missing or containing invalid JWTs, return 401 status code
        res.status(401).json({ "Error": "Missing or Containing invalid JWTs" });
    } else if (!req.body.name || !req.body.type || !req.body.length){
        res.status(400).json({ "Error": "The request object is missing at least one of the required attributes" });
    } else {
        post_boats(req.body.name, req.body.type, req.body.length, req.user.sub)
            .then(key => { res.status(201).json({ 
                "id": key.id, 
                "name": req.body.name, 
                "type": req.body.type, 
                "length": req.body.length, 
                "loads": [], 
                "owner": req.user.sub, 
                "self": `https://xueche-cs493-final.uw.r.appspot.com/boats/${key.id}`}); 
        });
    }
});

// Get all boats for a specific user, JWT required
router.get('/boats', function(req, res) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      // JWT is provided
      checkJwt(req, res, (err) => {
        if (err) {
          // Invalid JWT
          res.status(403).json({ "Error": "Invalid JWT" });
        } else {
          // Valid JWT
          get_boats(req, req.user.sub).then((results) => {
            const boats = results.boats.map((boat) => ({
              id: boat.id,
              name: boat.name,
              type: boat.type,
              length: boat.length,
              loads: boat.loads,
              owner: boat.owner,
              self: `https://xueche-cs493-final.uw.r.appspot.com/boats/${boat.id}`
            }));

            // Add pagination
            const response = { boats };
            if (results.boats.length === 5) {
                response.next = results.next;
            } 
  
            // Return the boats
            res.status(200).json(response);
          });
        }
      });
    } else {
      // No JWT provided
      res.status(401).json({ "Error": "No JWT provided" });
    }
  });
  
// Get a single boat, JWT required
router.get('/boats/:boat_id', function(req, res) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      // JWT is provided
      checkJwt(req, res, (err) => {
        if (err) {
          // Invalid JWT
          res.status(405).json({ "Error": "Invalid JWT" });
        } else {
          // Valid JWT, retrieve the boat and check ownership
          get_single_boat(req.params.boat_id).then((boat) => {
            if (!boat[0]) {
              res.status(404).json({ "Error": "No boat with this boat_id exists" });
            } else if (boat[0].owner !== req.user.sub) {
              res.status(403).json({ "Error": "The boat does not belong to the authenticated user" });
            } else {
              const boatInfo = boat[0];
              res.status(200).json({
                "id": boatInfo.id,
                "name": boatInfo.name,
                "type": boatInfo.type,
                "length": boatInfo.length,
                "loads": boatInfo.loads,
                "owner": boatInfo.owner,
                "self": `https://xueche-cs493-final.uw.r.appspot.com/boats/${boatInfo.id}`
              });
            }
          });
        }
      });
    } else {
      // No JWT provided
      res.status(401).json({ "Error": "No JWT provided" });
    }
  });
  

// Delete a boat, JWT required
router.delete('/boats/:boat_id', function(req, res) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        // JWT is provided
        checkJwt(req, res, (err) => {
            if (err) {
                // Invalid JWT
                res.status(405).json({ "Error": "Invalid JWT" });
            } else {
                // Valid JWT, retrieve the boat and check ownership
                get_single_boat(req.params.boat_id).then((boat) => {
                    if (!boat[0]) {
                        res.status(404).json({ "Error": "No boat with this boat_id exists" });
                    } else if (boat[0].owner !== req.user.sub) {
                        res.status(403).json({ "Error": "The boat does not belong to the authenticated user" });
                    } else {
                        // Remove all loads from the boat
                        for (var i = 0; i < boat[0].loads.length; i++) {
                            get_single_load(boat[0].loads[i].id)
                                .then(load => {
                                    put_loads(load[0].id, load[0].volume, load[0].item, load[0].creation_date, null);
                                });
                        }
                        delete_boats(req.params.boat_id)
                            .then(res.status(204).end());
                    }
                });
            }
        });
    } else {
        // No JWT provided
        res.status(401).json({ "Error": "No JWT provided" });
    }
});


// Update a boat by patching/ putting, JWT required, loads cannot be updated
router.patch('/boats/:boat_id', function(req, res) {
    if(req.get('content-type') !== 'application/json'){
        res.status(406).json({ "Error": "Server only accepts application/json data" });
    } else {
        update_boats(res, req);
    }
});
router.put('/boats/:boat_id', function(req, res) {
    if(req.get('content-type') !== 'application/json'){
        res.status(406).json({ "Error": "Server only accepts application/json data" });
    } else {
        update_boats(res, req);
    }
});
/* ------------- End Boats Controller Functions ------------- */

/* ------------- Begin Loads Model Functions ------------- */
// Post a load to the datastore
function post_loads(volume, item, creation_date) {
    var key = datastore.key(LOADS);
    const new_load = { "volume": volume, "item": item, "creation_date": creation_date, "carrier": null };
    return datastore.save({ "key": key, "data": new_load }).then(() => { return key });
}

// Get all loads, with pagination 5 loads per page
function get_loads(req) {
    const q = datastore.createQuery(LOADS).limit(5);
    const results = {};
    if (Object.keys(req.query).includes("cursor")) {
      q.start(req.query.cursor);
    }
    return datastore.runQuery(q).then((entities) => {
      results.loads = entities[0].map(fromDatastore);
      results.next = entities[1].moreResults !== Datastore.NO_MORE_RESULTS ? `${req.protocol}://${req.get("host")}${req.baseUrl}/loads?cursor=${entities[1].endCursor}` : null;
      return results;
    });
}

// Get a single load from the datastore
function get_single_load(id) {
    const key = datastore.key([LOADS, parseInt(id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return entity;
        } else {
            return entity.map(fromDatastore);
        }
    });
}

// Update a load in the datastore
function put_loads(id, volume, item, creation_date, carrier) {
    const key = datastore.key([LOADS, parseInt(id, 10)]);
    const loads = { "volume": volume, "item": item, "creation_date": creation_date, "carrier": carrier };
    return datastore.save({ "key": key, "data": loads });
}

// Edit a load, no JWT, carrier cannot be updated
function update_loads(res, req) {
    get_single_load(req.params.load_id).then((load) => {
        if (!load[0]) {
            res.status(404).json({ "Error": "No load with this load_id exists" });
        } else {
            // Update the load
            if (req.body.volume) {
                load[0].volume = req.body.volume;
            }

            if (req.body.item) {
                load[0].item = req.body.item;
            }

            if (req.body.creation_date) {
                load[0].creation_date = req.body.creation_date;
            }

            // If carrier is changed, return 406 status code
            if (req.body.carrier && req.body.carrier !== load[0].carrier) {
                res.status(406).json({ "Error": "Loading/unloading needs to use other endpoints" });
            } else {
                // No carrier change, save the load
                put_loads(req.params.load_id, load[0].volume, load[0].item, load[0].creation_date, load[0].carrier)
                    .then(() => {
                        res.status(200).json({
                            "id": req.params.load_id,
                            "volume": load[0].volume,
                            "item": load[0].item,
                            "creation_date": load[0].creation_date,
                            "carrier": load[0].carrier,
                            "self": `https://xueche-cs493-final.uw.r.appspot.com/loads/${req.params.load_id}`
                        });
                    })
                    .catch((error) => {
                        res.status(500).json({ "Error": "An error occurred while updating the load" });
                    });
            }
        }
    });
}

// Delete a load from the datastore
function delete_loads(id) {
    const loadKey = datastore.key([LOADS, parseInt(id, 10)]);
  
    return datastore.get(loadKey)
      .then((load) => {
        if (load[0] === undefined || load[0] === null) {
          return load;
        } else {
          if (load[0].carrier !== null) {
            const boatKey = datastore.key([BOATS, parseInt(load[0].carrier, 10)]);
  
            return datastore.get(boatKey)
              .then((boat) => {
                boat[0].loads = boat[0].loads.filter((item) => item !== id);
  
                return datastore.save({ "key": boatKey, "data": boat[0] })
                  .then(() => datastore.delete(loadKey)); // Delete the load entity
              });
          } else {
            return datastore.delete(loadKey); // Delete the load entity directly
          }
        }
    });
}
  
/* ------------- End Loads Model Functions ------------- */

/* ------------- Begin Loads Controller Functions ------------- */
// Add a new load, no JWT
router.post('/loads', function (req, res) {
    if(req.get('content-type') !== 'application/json'){
        res.status(406).json({ "Error": "Server only accepts application/json data" });
    } else if (!req.body.volume || !req.body.item || !req.body.creation_date){
        res.status(400).json({ "Error": "The request object is missing at least one of the required attributes" });
    } else {
        post_loads(req.body.volume, req.body.item, req.body.creation_date)
            .then(key => { res.status(201).json({ 
                "id": key.id, 
                "volume": req.body.volume, 
                "item": req.body.item, 
                "creation_date": req.body.creation_date, 
                "carrier": null, 
                "self": `https://xueche-cs493-final.uw.r.appspot.com/loads/${key.id}`}); 
        });
    }
});

// Get all loads, no JWT
router.get('/loads', function(req, res) {
    get_loads(req).then((results) => {
        const loads = results.loads.map((load) => ({
            id: load.id,
            volume: load.volume,
            item: load.item,
            creation_date: load.creation_date,
            carrier: load.carrier,
            self: `https://xueche-cs493-final.uw.r.appspot.com/loads/${load.id}`
        }));

        // Add pagination
        const response = { loads };
        if (results.loads.length === 5) {
            response.next = results.next;
        } 

        // Return the loads
        res.status(200).json(response);
    });
});

// Get a single load, no JWT
router.get('/loads/:load_id', function(req, res) {
    get_single_load(req.params.load_id).then((load) => {
        if (!load[0]) {
            res.status(404).json({ "Error": "No load with this load_id exists" });
        } else {
            const loadInfo = load[0];
            res.status(200).json({
                "id": loadInfo.id,
                "volume": loadInfo.volume,
                "item": loadInfo.item,
                "creation_date": loadInfo.creation_date,
                "carrier": loadInfo.carrier,
                "self": `https://xueche-cs493-final.uw.r.appspot.com/loads/${loadInfo.id}`
            });
        }
    });
});

// Update a load by patching/ putting, no JWT, carrier cannot be updated
router.patch('/loads/:load_id', function(req, res) {
    if(req.get('content-type') !== 'application/json'){
        res.status(406).json({ "Error": "Server only accepts application/json data" });
    } else {
        update_loads(res, req);
    }
});
router.put('/loads/:load_id', function(req, res) {
    if(req.get('content-type') !== 'application/json'){
        res.status(406).json({ "Error": "Server only accepts application/json data" });
    } else {
        update_loads(res, req);
    }
});

// Delete a load
router.delete('/loads/:id', function(req, res) {
    get_single_load(req.params.id)
      .then((entity) => {
        // Check if load exists
        if (entity[0] === undefined || entity[0] === null) {
          res.status(404).json({ "Error": "No load with this load_id exists" });
        } else if (entity[0].carrier !== null) {
          // If load is carried by a boat, delete the load from the boat
          get_single_boat(entity[0].carrier.id)
            .then((boat) => {
              for (var i = 0; i < boat[0].loads.length; i++) {
                if (boat[0].loads[i].id === req.params.id) {
                  boat[0].loads.splice(i, 1);
                  break; // Exit the loop after removing the load
                }
              }
  
              put_boats(
                entity[0].carrier.id,
                boat[0].name,
                boat[0].type,
                boat[0].length,
                boat[0].loads,
                boat[0].owner
              )
                .then(() => delete_loads(req.params.id))
                .then(() => res.status(204).end());
            });
        } else {
          delete_loads(req.params.id)
            .then(() => res.status(204).end());
        }
      });
  });
  
/* ------------- End Loads Controller Functions ------------- */

/* ------------- Begin Loading/unloading Controller Functions ------------- */
// Load a load onto a boat, JWT required
router.put('/boats/:boat_id/loads/:load_id', function (req, res) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        // JWT is provided
        checkJwt(req, res, (err) => {
            if (err) {
                // Invalid JWT
                res.status(405).json({ "Error": "Invalid JWT" });
            } else {
                // Valid JWT, retrieve the boat and check ownership
                get_single_boat(req.params.boat_id).then((boat) => {
                    if (!boat[0]) {
                        res.status(404).json({ "Error": "No boat with this boat_id exists" });
                      } else if (boat[0].owner !== req.user.sub) {
                        res.status(403).json({ "Error": "The boat does not belong to the authenticated user" });
                      } else {
                        // Check if load is already carried by a boat
                        get_single_load(req.params.load_id).then((load) => {
                            if (!load[0]) {
                                res.status(404).json({ "Error": "No load with this load_id exists" });
                            } else if (load[0].carrier !== null) {
                                res.status(403).json({ "Error": "The load is already carried by another boat" });
                            } else {
                                // Update the load and the boat
                                boat[0].loads.push({
                                    "id": req.params.load_id,
                                    "item": load[0].item,
                                });
        
                                // Add the boat to the load
                                load[0].carrier = {
                                    "id": req.params.boat_id,
                                    "name": boat[0].name,
                                };
        
                                // Update the datastore
                                put_boats(req.params.boat_id, boat[0].name, boat[0].type, boat[0].length, boat[0].loads, boat[0].owner)
                                    .then(put_loads(req.params.load_id, load[0].volume, load[0].item, load[0].creation_date, load[0].carrier)
                                        .then(res.status(204).end()));
                            }
                        });
                      }
                });
            }
        });
    } else {
        // No JWT provided
        res.status(401).json({ "Error": "No JWT provided" });
    }
});

// Unload a load from a boat, JWT required
router.delete('/boats/:boat_id/loads/:load_id', function (req, res) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        // JWT is provided
        checkJwt(req, res, (err) => {
            if (err) {
                // Invalid JWT
                res.status(405).json({ "Error": "Invalid JWT" });
            } else {
                // Valid JWT, retrieve the boat and check ownership
                get_single_boat(req.params.boat_id).then((boat) => {
                    if (!boat[0]) {
                        res.status(404).json({ "Error": "No boat with this boat_id exists" });
                      } else if (boat[0].owner !== req.user.sub) {
                        res.status(403).json({ "Error": "The boat does not belong to the authenticated user" });
                      } else {
                        // Check if load is carried by the boat
                        get_single_load(req.params.load_id).then((load) => {
                            if (!load[0]) {
                                res.status(404).json({ "Error": "No load with this load_id exists" });
                            } else if (load[0].carrier === null || load[0].carrier.id !== req.params.boat_id) {
                                res.status(403).json({ "Error": "The load is not carried by the boat" });
                            } else {
                                // Remove the load from the boat
                                for (var i = 0; i < boat[0].loads.length; i++) {
                                    if (boat[0].loads[i].id === req.params.load_id) {
                                        boat[0].loads.splice(i, 1);
                                    }
                                }
                                load[0].carrier = null;
                                put_boats(req.params.boat_id, boat[0].name, boat[0].type, boat[0].length, boat[0].loads, boat[0].owner)
                                    .then(put_loads(req.params.load_id, load[0].volume, load[0].item, load[0].creation_date, load[0].carrier)
                                        .then(res.status(204).end()));
                                    }
                        });
                    }
                });
            }
        });
    } else {
        // No JWT provided
        res.status(401).json({ "Error": "No JWT provided" });
    }
});
/* ------------- End Loading/unloading Controller Functions ------------- */

app.use('/', router);
app.use('/login', login);

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}...`);
});