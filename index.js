const express = require('express');
const helmet = require('helmet');
const cors = require('cors')
const cookieParser = require('cookie-parser');
const { mongoConnection } = require('./configs/mongoConnect');
const swaggerUI = require("swagger-ui-express");
const swaggerJsDoc = require("swagger-jsdoc")

const authRouter = require("./routers/authRouter.js")

const options = {
    definition: {
        openapi: "3.0.0",
        info: {
            title: "Authencation API",
            version: "1.0.0",
            description: "API for user registration, login, logout, and email verification",
        },
        servers: [
            {
                url: "http://localhost:3000/api",
            },
        ],
        
    },
    apis: ["./routers/*.js"], 
};
const specs = swaggerJsDoc(options);

const app = express();

app.use("/api-docs", swaggerUI.serve, swaggerUI.setup(specs))
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
