var fs = require('fs');
var restify = require('restify');
var bcrypt = require('bcrypt');
var Logger = require('bunyan');

var credentials = JSON.parse(fs.readFileSync('credentials.json'));

var log = new Logger({
	name: 'codetest',
	streams: [ { path: 'server.log', level: "debug" } ],
	serializers: restify.bunyan.serializers
});

var server = restify.createServer({
		certificate: fs.readFileSync('server.crt'),
		key: fs.readFileSync('server.key'),
		name: "code Test",
		log: log
});

server.pre(function(req, res, next) {
	req.headers["content-type"] = "text/plain";
	next();
});

server.use(restify.authorizationParser());
server.use(restify.bodyParser());

server.use(function(req, res, next) {
	if (req.authorization == undefined ||
		req.authorization.basic == undefined ||
		req.authorization.basic.username == undefined ||
		req.authorization.basic.password == undefined ) {
		return next(new restify.ForbiddenError("Invalid username or password"));
	}
	bcrypt.compare(req.authorization.basic.password, credentials[req.authorization.basic.username], function(err, res) {
		if (err != undefined || res != true) {
			// Strip the auth headers for logging
			req.headers.authorization = undefined;
			req.log.info({req:req,res:res,user:req.authorization.basic.username},"failed login");
			return next(new restify.ForbiddenError("Invalid username or password"));
		} else {
			return next();
		}
	});
});

server.post('/', function(req, res, next) {
	var output = {"count":0, "words": {}}
	if (req.body != undefined) {
		var words = req.body.split(/\W/).forEach(function(word) {
			if ( word != '' ) {
				if (output.words[word.toLowerCase()] != undefined)
					output.words[word.toLowerCase()]++;
				else
					output.words[word.toLowerCase()] = 1;
				output.count += 1;
			}
		});
	}
	res.send(output);
	// Strip the auth headers for logging
	req.headers.authorization = undefined;
	req.log.debug({req:req, res:res});
	next();
});

server.listen(443, function() {
	try {
		if (process.getuid() == 0) {
			process.setgid('www-data');
			process.setuid('www-data');
		}
		log.info("Listening on %s", server.url);
	} catch (err) {
		log.error('Cannot drop privileges, exiting');
		process.exit(1);
	}
});
