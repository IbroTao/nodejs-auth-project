const express = require('express');
const helmet = require('helmet');
const cors = require('cors')
const cookieParser = require('cookie-parser');
const { mongoConnection } = require('./configs/mongoConnect');

const authRouter = require("./routers/authRouter.js")

const app = express();

app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({extended: true}));

app.use("/api/auth", authRouter)
app.get('/', (req, res) => {
    res.json({message: "Hello from the server!"})
})

const port = process.env.PORT;

const runApp = (port) => {
    mongoConnection().then(
        res=>{
            app.listen(port);
            console.log("Server running✔ 👀")
        }
    ).catch(
        err=>{
            console.log(err);
        }
    )
};

runApp(port);
