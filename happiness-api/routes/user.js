const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const moment = require('moment');

/* GET users listing. */
router.get('/', function (req, res, next) {
	res.send('respond with a resource');
});

//Register POST
router.post('/register', function (req, res, next) {
	const email = req.body.email;
	const password = req.body.password;

	//if email or password is missing raise error
	if (!email || !password) {
		return res.status(400).json({
			error: true,
			message: 'Request body incomplete, both email and password are required',
		});
	}
	const queryUsers = req.db
		.from('users')
		.select('*')
		.where('email', '=', email);
	queryUsers
		.then((users) => {
			//Check if user exists already
			if (users.length > 0) {
				return res
					.status(409)
					.json({ error: true, message: 'User already exists' });
			}
			//encryption
			const saltRounds = 10;
			const hash = bcrypt.hashSync(password, saltRounds);
			return req.db.from('users').insert({ email, hash });
		})
		.then((result) => {
			//check if error or db request is being passed from the previous then
			if (result.statusCode !== 409) {
				return res.status(201).json({ message: 'User created' });
			}
		});
});

//Login POST
router.post('/login', function (req, res, next) {
	const bodies = req.body;
	const email = bodies.email;
	const password = bodies.password;

	//If email or password have not been passed
	if (!email || !password) {
		return res.status(400).json({
			error: true,
			message: 'Request body incomplete, both email and password are required',
		});
	}

	const queryUsers = req.db
		.from('users')
		.select('*')
		.where('email', '=', email);
	queryUsers
		.then((users) => {
			//If user does not exist
			if (users[0] === undefined) {
				return res
					.status(401)
					.json({ error: true, message: 'User does not exist' });
			} else {
				const user = users[0];
				return bcrypt.compare(password, user.hash);
			}
		})
		.then((match) => {
			//Check if a res status is being passed from the previous then
			if (match.statusCode === 401) {
				//Do nothing
			}
			//If passwords do not match
			else if (!match) {
				return res.status(401).json({
					error: true,
					message: 'Incorrect email or password',
				});
			}
			//If all the tests are passed then continue
			else {
				//return Token with type and expiration
				const secretKey = 'secret key';
				const expires_in = 60 * 60 * 24;
				const exp = Date.now() + expires_in * 1000;
				const token = jwt.sign({ email, exp }, secretKey);
				return res
					.status(200)
					.json({ token_type: 'Bearer', token, expires_in });
			}
		});
});

//Authorize funtion
const authorize = (req, res, next) => {
	const authorization = req.headers.authorization;
	let token = null;

	//If authorization header has not been passed
	if (!authorization) {
		return res.status(401).json({
			error: true,
			message: "Authorization header ('Bearer token') not found",
		});
	}
	//If the authorization header does not have 2 elements
	else if (authorization.split(' ').length !== 2) {
		return res.status(401).json({
			error: true,
			message: 'Authorization header is malformed',
		});
	}
	//Retrieve token if previous tests are passed
	else {
		token = authorization.split(' ')[1];
	}

	//Verify JWT and check expiration date
	try {
		const decoded = jwt.verify(token, 'secret key');
		if (decoded.exp < Date.now()) {
			return res
				.status(401)
				.json({ error: true, message: 'Token has expired' });
		}
		//Permit user to advance to route
		next();
	} catch (e) {
		return res.status(401).json({
			error: true,
			message: 'Invalid JWT token',
		});
	}
};

//Profile GET
router.get('/:email/profile', function (req, res, next) {
	const authorization = req.headers.authorization;

	//If no authorization has been passed then give them public info
	if (authorization === undefined) {
		req.db
			.from('users')
			.first('email', 'firstName', 'lastName')
			.where('email', '=', req.params.email)
			.then((rows) => {
				//If nothing is returned
				if (!rows) {
					return res
						.status(404)
						.json({ error: true, message: 'User not found' });
				}
				//kept failling the git hub test so did this cause it would return undefined, not null
				for (let x in rows) {
					if (x === undefined) {
						rows.x = null;
					}
				}
				return res.status(200).json({ ...rows });
			})
			.catch((err) => {
				return res.json({ error: true, message: 'Error in MySQL query' });
			});
	}
	//if authorization has been passed
	else {
		//run authorization function
		authorize;

		//If authorize passed then retrieve token and decode it
		const authorization = req.headers.authorization;
		token = authorization.split(' ')[1];
		const decoded = jwt.verify(token, 'secret key');

		//if the parameter email and decoded email dont match give them public info
		if (req.params.email !== decoded.email) {
			req.db
				.from('users')
				.first('email', 'firstName', 'lastName')
				.where('email', '=', req.params.email)
				.then((rows) => {
					//If nothing is returned
					if (!rows) {
						return res
							.status(404)
							.json({ error: true, message: 'User not found' });
					}
					//Trying to get Github tests to work cause they say I return undefined but the tests I do return null????
					if (rows.firstName === undefined) {
						rows.firstName = null;
					}
					if (rows.lastName === undefined) {
						rows.lastName = null;
					}

					return res.status(200).json({ ...rows });
				})
				.catch((err) => {
					return res.json({ error: true, message: 'Error in MySQL query' });
				});
		}
		//If parameter email and decoded email are the same then give them more info
		else {
			req.db
				.from('users')
				.first('email', 'firstName', 'lastName', 'dob', 'address')
				.where('email', '=', req.params.email)
				.then((rows) => {
					//If nothing is returned
					if (!rows) {
						return res
							.status(404)
							.json({ error: true, message: 'User not found' });
					}

					//Trying to get Github tests to work cause they say I return undefined but the tests I do return null????
					if (rows.firstName === undefined) {
						rows.firstName = null;
					}
					if (rows.lastName === undefined) {
						rows.lastName = null;
					}
					return res.status(200).json({ ...rows });
				})
				.catch((err) => {
					return res.json({ error: true, message: 'Error in MySQL query' });
				});
		}
	}
});

//Profile PUT
router.put('/:email/profile', authorize, function (req, res, next) {
	//Retrieve token and the email
	const authorization = req.headers.authorization;
	token = authorization.split(' ')[1];
	const decoded = jwt.verify(token, 'secret key');

	const email = req.params.email;
	const firstName = req.body.firstName;
	const lastName = req.body.lastName;
	const dob = req.body.dob;
	const address = req.body.address;

	//If parameter email and decoded email do not match
	if (email !== decoded.email) {
		return res.status(403).json({
			error: true,
			message: 'Forbidden',
		});
	}

	//Check if any inputs are null
	if (!lastName || !firstName || !dob || !address) {
		return res.status(400).json({
			error: true,
			message:
				'Request body incomplete: firstName, lastName, dob and address are required.',
		});
	}
	//Check if these inputs are string
	if (
		typeof firstName !== 'string' ||
		typeof lastName !== 'string' ||
		typeof address !== 'string'
	) {
		return res.status(400).json({
			error: true,
			message:
				'Request body invalid, firstName, lastName and address must be strings only.',
		});
	}

	//Split date and check if each part is a number or certain length
	let date = dob.split('-');
	if (
		!/\d{4}$/.test(date[0]) ||
		!/\d{2}$/.test(date[1]) ||
		!/\d{2}$/.test(date[2])
	) {
		return res.status(400).json({
			error: true,
			message: 'Invalid input: dob must be a real date in format YYYY-MM-DD.',
		});
	}

	//Check if date is invalid
	if (isNaN(new Date(dob).getTime()) || !moment(dob, 'YYYY-MM-DD').isValid()) {
		return res.status(400).json({
			error: true,
			message: 'Invalid input: dob must be a real date in format YYYY-MM-DD.',
		});
	}
	//Check if date is in the future
	if (new Date() < new Date(dob)) {
		return res.status(400).json({
			error: true,
			message: 'Invalid input: dob must be a date in the past.',
		});
	}

	req.db
		.from('users')
		.where('email', '=', email)
		.update({
			firstName: firstName,
			lastName: lastName,
			dob: dob,
			address: address,
		})
		.then((rows) => {
			//Check if anything is returned
			if (!rows) {
				return res
					.status(404)
					.json({ error: true, message: 'User does not exist' });
			}
			return res.status(200).json({ email, firstName, lastName, dob, address });
		})
		.catch((error) => {
			return res.status(500).json({ message: 'Database error - not updated' });
		});
});

module.exports = router;
