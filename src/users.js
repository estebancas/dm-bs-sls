const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");

const {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  ScanCommand,
  UpdateCommand,
} = require("@aws-sdk/lib-dynamodb");

const express = require("express");
const serverless = require("serverless-http");

const app = express();

const USERS_TABLE = process.env.USERS_TABLE;
const client = new DynamoDBClient();
const docClient = DynamoDBDocumentClient.from(client);
const tokenSecret = "dm_bs_secret";

app.use(express.json());

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, tokenSecret, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    req.user = user;
    next();
  });
};

const findUserById = async (id) => {
  const params = {
    TableName: USERS_TABLE,
    Key: {
      id,
    },
  };

  try {
    const command = new GetCommand(params);
    const { Item } = await docClient.send(command);
    if (Item) {
      return Item;
    } else {
      return null;
    }
  } catch (error) {
    return null;
  }
};

app.get("/users/:userId", authenticateJWT, async (req, res) => {
  const userId = req.params.userId;

  try {
    const user = await findUserById(userId);
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ error: "No se ha encontrado el usuario" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "No se ha encontrado el usuario" });
  }
});

const findUserByEmail = async (email) => {
  const params = {
    TableName: USERS_TABLE,
    FilterExpression: "email = :emailValue",
    ExpressionAttributeValues: {
      ":emailValue": email,
    },
  };

  try {
    const data = await docClient.send(new ScanCommand(params));
    if (data.Items.length > 0) {
      return data.Items[0];
    } else {
      return null;
    }
  } catch (error) {
    return null;
  }
};

app.post("/users", async (req, res) => {
  const { name, email } = req.body;

  if (typeof name !== "string") {
    return res.status(400).json({ error: '"name" must be a string' });
  }

  if (email) {
    const emailExist = await findUserByEmail(email);

    if (emailExist) {
      return res.status(400).json({ error: "El correo ya esta en uso" });
    }
  }

  const id = uuidv4();

  const params = {
    TableName: USERS_TABLE,
    Item: { email, name, id },
  };

  try {
    const command = new PutCommand(params);
    await docClient.send(command);

    const token = jwt.sign({ id, name }, tokenSecret, { expiresIn: "30d" });

    res.json({ email, name, token, id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not create user" });
  }
});

app.post("/users/login", async (req, res) => {
  const { name, email } = req.body;

  if (typeof name !== "string") {
    return res.status(400).json({ error: '"name" must be a string' });
  }

  if (email) {
    const userExist = await findUserByEmail(email);
    const token = jwt.sign(
      { id: userExist.id, name: userExist.name },
      tokenSecret,
      { expiresIn: "30d" }
    );

    if (userExist && userExist.name === name) {
      res.json({ ...userExist, token });
    } else {
      res.status(500).json({ error: "Los datos ingresados son incorrectos" });
    }
  }
});

app.put("/users", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const { comment, survey, email } = req.body;

  if (!comment && !survey && email) {
    return res.status(500).json({ error: "bad request" });
  }

  const user = await findUserById(userId);

  if (!user) {
    return res.status(400).json({ error: "Usuario no existe" });
  }

  if (email && email !== user.email) {
    const emailExist = await findUserByEmail(email);

    if (emailExist) {
      return res.status(400).json({ error: "El correo ya esta en uso" });
    }
  }

  const params = {
    TableName: USERS_TABLE,
    Key: {
      id: userId,
    },
    UpdateExpression: `SET ${email ? ", #em = :e" : ""} ${
      comment ? ", #comment = :comment" : ""
    } ${survey ? ", #survey = :survey" : ""}`,
    ExpressionAttributeNames: {
      ...(email ? { "#em": "email" } : {}),
      ...(comment ? { "#comment": "comment" } : {}),
      ...(survey ? { "#survey": "survey" } : {}),
    },
    ExpressionAttributeValues: {
      ...(email ? { ":e": email } : {}),
      ...(comment ? { ":comment": comment } : {}),
      ...(survey ? { ":survey": survey } : {}),
    },
    ReturnValues: "ALL_NEW",
  };

  try {
    const command = new UpdateCommand(params);
    const reponseData = await docClient.send(command);
    res.json(reponseData.Attributes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudo actualizar el usuario" });
  }
});

app.use((req, res, next) => {
  return res.status(404).json({
    error: "Not Found",
  });
});

exports.handler = serverless(app);
