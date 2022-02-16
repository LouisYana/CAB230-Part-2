const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

const swaggerUI = require('swagger-ui-express');
const swaggerDocument = require('../docs/swagger.json');

/* GET home page. */
router.use('/', swaggerUI.serve);
router.get('/', swaggerUI.setup(swaggerDocument));

//Rankings GET
router.get('/rankings', function (req, res, next) {
	let queries = req.query;
	let year = queries.year;
	let country = queries.country;

	//Check if any queries are not year or country
	for (let x in queries) {
		if (x !== 'year' && x !== 'country') {
			return res.status(400).json({
				error: true,
				message:
					'Invalid query parameters. Only year and country are permitted.',
			});
		}
	}
	//Check if country contains numbers
	if (/\d/.test(country)) {
		return res.status(400).json({
			error: true,
			message:
				'Invalid country format. Country query parameter cannot contain numbers.',
		});
	}
	//If year exists check if it is a number that is 4 digits long
	else if (year !== undefined && !/^\d{4}$/.test(year)) {
		return res.status(400).json({
			error: true,
			message: 'Invalid year format. Format must be yyyy.',
		});
	}
	//If year and country parameter have been passed
	if (year !== undefined && country !== undefined) {
		req.db
			.from('rankings')
			.select('rank', 'country', 'score', 'year')
			.where('year', '=', year)
			.where('country', '=', country)
			.orderBy([{ column: 'year', order: 'desc' }, 'rank'])
			.then((rows) => {
				return res.status(200).json(rows);
			})
			.catch((err) => {
				return res.json({ error: true, message: 'Error in MySQL query' });
			});
	}
	//If year has been passed but not country
	else if (year !== undefined && country === undefined) {
		req.db
			.from('rankings')
			.select('rank', 'country', 'score', 'year')
			.where('year', '=', year)
			.orderBy([{ column: 'year', order: 'desc' }, 'rank'])
			.then((rows) => {
				return res.status(200).json(rows);
			})
			.catch((err) => {
				return res.json({ error: true, message: 'Error in MySQL query' });
			});
	}
	//If year has not been passed but country has
	else if (year === undefined && country !== undefined) {
		req.db
			.from('rankings')
			.select('rank', 'country', 'score', 'year')
			.where('country', '=', country)
			.orderBy([{ column: 'year', order: 'desc' }, 'rank'])
			.then((rows) => {
				return res.status(200).json(rows);
			})
			.catch((err) => {
				return res.json({ error: true, message: 'Error in MySQL query' });
			});
	}
	//If country and year have not been passed
	else {
		req.db
			.from('rankings')
			.select('rank', 'country', 'score', 'year')
			.orderBy([{ column: 'year', order: 'desc' }, 'rank'])
			.then((rows) => {
				return res.status(200).json(rows);
			})
			.catch((err) => {
				return res.json({ error: true, message: 'Error in MySQL query' });
			});
	}
});

//Country GET
router.get('/countries', function (req, res, next) {
	//Check if any query parameters have been passed
	if (req.query.params !== undefined) {
		return res.status(400).json({
			Error: true,
			Message: 'Invalid query parameters. Query parameters are not permitted.',
		});
	} else {
		req.db
			.from('rankings')
			.select('country')
			.distinct()
			.orderBy('country')
			.then((rows) => {
				//return only countries
				country = rows.map((x) => x.country);
				return res.status(200).json(country);
			})
			.catch((err) => {
				return res.json({ error: true, message: 'Error in MySQL query' });
			});
	}
});

//Authorize function
const authorize = (req, res, next) => {
	const authorization = req.headers.authorization;
	let token = null;
	//Check if there is any authorization header being passed
	if (!authorization) {
		return res.status(401).json({
			error: true,
			message: "Authorization header ('Bearer token') not found",
		});
	}
	//Check if the authorization header cannot be split into two
	else if (authorization.split(' ').length !== 2) {
		return res.status(401).json({
			error: true,
			message: 'Authorization header is malformed',
		});
	} else {
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

//Factors GET
router.get('/factors/:year', authorize, function (req, res, next) {
	queries = req.query;
	let year = req.params.year;
	let limit = queries.limit;
	//If no limit is being passed make limit a large number to display everything
	if (limit === undefined) {
		limit = 10000;
	}
	//If limit is negative or contains non integers then raise an error
	else if (limit < 0 || !/^\d+$/.test(limit)) {
		return res.status(400).json({
			error: true,
			message: 'Invalid limit query. Limit must be a positive number.',
		});
	}

	let country = queries.country;
	//Test if country has any number values in it
	if (/\d/.test(country)) {
		return res.status(400).json({
			error: true,
			message:
				'Invalid country format. Country query parameter cannot contain numbers.',
		});
	}
	//If year is being passed through and it does not contain 4 integers then raise an error
	else if (year !== undefined && !/^\d{4}$/.test(year)) {
		return res.status(400).json({
			error: true,
			message: 'Invalid year format. Format must be yyyy.',
		});
	}

	//Check if query is not limit or year
	for (let x in queries) {
		if (x !== 'limit' && x !== 'country') {
			return res.status(400).json({
				error: true,
				message:
					'Invalid query parameters. Only limit and country are permitted.',
			});
		}
	}

	//If not country query has been passed through
	if (country === undefined) {
		req.db
			.from('rankings')
			.select(
				'rank',
				'country',
				'score',
				'economy',
				'family',
				'health',
				'freedom',
				'generosity',
				'trust'
			)
			.where('year', '=', year)
			.limit(limit)
			.then((rows) => {
				return res.status(200).json(rows);
			})
			.catch((err) => {
				return res.json({ error: true, message: 'Error in MySQL query' });
			});
	}
	//If country query has been passed through
	else {
		req.db
			.from('rankings')
			.select(
				'rank',
				'country',
				'score',
				'economy',
				'family',
				'health',
				'freedom',
				'generosity',
				'trust'
			)
			.where('year', '=', year)
			.where('country', '=', country)
			.limit(limit)
			.then((rows) => {
				return res.status(200).json(rows);
			})
			.catch((err) => {
				return res.json({ error: true, message: 'Error in MySQL query' });
			});
	}
});

module.exports = router;
