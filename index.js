
require('dotenv').config();

const {APP_PORT, LICHESS_CLIENT_ID, LICHESS_CLIENT_SECRET, GOV_WSDL,
    SESSION_SECRET, MONGODB_URL, LICHESS_TEAM_ID, LICHESS_TEAM_ADMIN} = process.env;

const express = require('express');
const oauth = require('simple-oauth2');
const axios = require('axios');
const crypto = require('crypto');
const soap = require('soap');
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
const ndjson = require('ndjson');
const {twig} = require('twig');

const api = axios.create({
    baseURL: 'https://lichess.org/',
});

mongoose = require('mongoose');
mongoose.connect(MONGODB_URL, {useNewUrlParser: true});


const playerSchema = new mongoose.Schema({
    userId: String,
    userName: String,
    firstName: String,
    lastName: String,
    birthYear: Number,
    govId: String,
    govIdSignature: String,
    banned: {type: Boolean, default: false}
});

playerSchema.index({govIdSignature: 1});

const Player = mongoose.model('Player', playerSchema);

const scopes = ['preference:read', 'team:write'];

const oauth2 = oauth.create({
    client: {id: LICHESS_CLIENT_ID, secret: LICHESS_CLIENT_SECRET},
    auth: {
        tokenHost: 'https://oauth.lichess.org',
        tokenPath: '/oauth',
        authorizePath: '/oauth/authorize'
    }
});

const app = express();

app.set( 'view engine', 'twig' );

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    store: new MongoStore({ mongooseConnection: mongoose.connection })
}));

function getUserIds(stream) {
    return new Promise((resolve, reject) => {
        const userIds = [];

        stream.on('data', user => userIds.push(user.id))
            .on('end', () => resolve(userIds))
            .on('error', (err) => reject(err));
    });
}

async function getTeamMembers(authToken) {
    const {data} = await api.get('/team/' + LICHESS_TEAM_ID + '/users', {
        headers: {'Authorization': 'Bearer ' + authToken},
        responseType: 'stream'
    });

    return getUserIds(data.pipe(ndjson.parse()));
}

async function verifyUserGovId(id, firstName, lastName, birthYear) {
    const soapClient = await soap.createClientAsync(GOV_WSDL);

    const [{TCKimlikNoDogrulaResult: status}] = await soapClient.TCKimlikNoDogrulaAsync({
        TCKimlikNo: id,
        Ad: firstName.toLocaleUpperCase('tr-TR'),
        Soyad: lastName.toLocaleUpperCase('tr-TR'),
        DogumYili: birthYear
    });

    return status;
}

async function kickTeamMember(userId, authToken) {
    const {data: {ok}} = await api.post('/team/' + LICHESS_TEAM_ID + '/kick/' + userId, {}, {
        headers: {'Authorization': 'Bearer ' + authToken}
    });

    return ok;
}

async function joinTeam(authToken) {
    const {data:{ok}} = await api.post('/team/' + LICHESS_TEAM_ID + '/join', {}, {
        headers: {'Authorization': 'Bearer ' + authToken}
    });

    return ok;
}

async function getUserInfo(authToken) {
    const {data} = api.get('/api/account', {
        headers: { 'Authorization': 'Bearer ' + token.access_token }
    });

    return data;
}

app.get('/', (req, res) => res.render('index/index.html.twig'));

app.get('/messages/:messageType', (req, res) => {

    const {messageType} = req.params;

    if (['success', 'banned', 'error'].indexOf(messageType) === -1) {
        return res.redirect('/');
    }

    res.render('messages/' + messageType + '.html.twig');
});

app.get('/auth', (req, res) => {

    const nonce = crypto.randomBytes(32).toString('hex');

    req.session.returnUrl =  req.query.returnUrl || '/';

    res.redirect(oauth2.authorizationCode.authorizeURL({
        state: nonce,
        redirect_uri: req.protocol + '://' + req.hostname + '/callback',
        scope: scopes
    }));
});

app.get('/callback', async (req, res) => {

    const returnUrl = req.session.returnUrl || '/';

    try {
        const result = await oauth2.authorizationCode.getToken({
            code: req.query.code,
            redirect_uri: req.protocol + '://' + req.hostname + '/callback',
            scope: scopes
        });

        const {token} = oauth2.accessToken.create(result);

        if (!token) {
            throw new Error('Token not exists');
        }

        const {id:userId, username} = await getUserInfo(token.access);

        req.session.userId = userId;
        req.session.userName = username;
        req.session.authToken = token.access_token;

        res.redirect(303, returnUrl);

    } catch (err) {
        console.log(err.message);
        res.redirect(303, '/');
    }

});

app.get('/verify/gov', async (req, res) => {

    const {userId} = req.session;

    if (!userId) {
        return res.redirect(303, '/auth?returnUrl=/verify/gov');
    }

    const date = new Date();

    try {
        const player = await Player.findOne({userId});

        if (!player) {
            return res.render('verify/gov.html.twig', {
                year: date.getFullYear() - 7
            });
        }

        if (player.banned) {
            return res.redirect(303, '/messages/banned');
        }

        if (await joinTeam(req.session.authToken)) {
            res.redirect(303, '/messages/success');
        } else {
            res.redirect(303, '/messages/error');
        }

    } catch (err) {
        console.log(err.message);
        res.redirect(303, '/messages/error');
    }

});

app.post('/verify/gov', async (req, res) => {

    const {id, name, surname, year} = req.body;
    const {userId, userName} = req.session;

    if (!userId) {
        return res.redirect(303, '/auth?returnUrl=/verify/gov');
    }

    try {
        const status = await verifyUserGovId(id, name, surname, year);

        if (!status) {
            return res.redirect(303, '/verify/gov');
        }

        const idSig = crypto.createHash('sha1')
            .update(id, 'ascii').digest('hex');

        const bannedPlayers = await Player.find({
            govIdSignature: idSig,
            banned: true
        });

        if (bannedPlayers.length > 0) {

            if (!bannedPlayers.find(bannedPlayer => bannedPlayer.userId === req.session.userId)) {
                await Player.create({
                    userId,
                    userName,
                    firstName: name,
                    lastName: surname,
                    birthYear: year,
                    govId: id.replace(/(?<=\d{3})\d{5}/, '*****'), // masked gov id
                    govIdSignature: idSig,
                    banned: true
                });
            }

            return res.redirect(303, '/messages/banned');
        }

        if (!await joinTeam(req.session.authToken)) {

            res.redirect(303, '/messages/error');

        } else {
            await Player.create({
                userId,
                userName,
                firstName: name,
                lastName: surname,
                birthYear: year,
                govId: id.replace(/(?<=\d{3})\d{5}/, '*****'), // masked gov id
                govIdSignature: idSig,
                banned: false
            });

            res.redirect(303, '/messages/success');
        }

    } catch (err) {
        console.log(err.message);
        res.redirect(303, '/messages/error');
    }

});



app.get('/players/:playerType(waiting|verified)', async (req, res) => {

    const {userId: adminId} = req.session;
    const {playerType} = req.params;

    if (!adminId) {
        return res.redirect(303, '/auth?returnUrl=/players/' + playerType);
    }

    if (adminId !== LICHESS_TEAM_ADMIN) {
        return res.redirect(303, '/');
    }

    try {
        const userIds = await getTeamMembers(req.session.authToken);

        res.render('players/' + playerType + '.html.twig', {
            players: await Player.find({
                userId: {[playerType === 'waiting' ? '$nin' : '$in']: userIds},
                banned: false
            })
        });

    } catch (err) {

        console.log(err);
        res.redirect(303, '/messages/error');

    }

});

app.get('/players/banned', async (req, res) => {

    const {userId: adminId} = req.session;

    if (!adminId) {
        return res.redirect(303, '/auth?returnUrl=/players/banned');
    }

    if (adminId !== LICHESS_TEAM_ADMIN) {
        return res.redirect(303, '/');
    }

    try {

        res.render('players/banned.html.twig', {
            players: await Player.find({banned: true})
        });

    } catch (err) {

        console.log(err);
        res.redirect(303, '/messages/error');

    }



});

app.post('/players/ban', async (req, res) => {

    const {userId: adminId} = req.session;

    if (!adminId) {
        return res.redirect(303, '/auth?returnUrl=/players/verified');
    }

    if (adminId !== LICHESS_TEAM_ADMIN) {
        return res.redirect(303, '/');
    }

    const {user: userId} =  req.body;

    try {
        const [kickStatus, player] = await Promise.all([
            kickTeamMember(userId, req.session.authToken),
            Player.findOneAndUpdate({userId}, {banned: true})
        ]);

        res.redirect(303, '/players/verified');
    } catch (err) {
        console.log(err);
        res.redirect(303, '/messages/error');
    }

});

app.post('/players/unban', async (req, res)  => {

    const {userId: adminId} = req.session;

    if (!adminId) {
        return res.redirect(303, '/auth?returnUrl=/players/banned');
    }

    if (adminId !== LICHESS_TEAM_ADMIN) {
        return res.redirect(303, '/');
    }

    const {user: userId} =  req.body;

    try {
        await Player.findOneAndUpdate({userId}, {banned: false});
        res.redirect(303, '/players/verified');
    } catch (err) {
        console.log(err);
        res.redirect(303, '/messages/error');
    }

});

app.listen(APP_PORT, () => console.log(`Express listening on port ${APP_PORT}!`));


