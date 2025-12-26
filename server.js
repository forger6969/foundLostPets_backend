// ===================================
// PET FINDER PLATFORM - BACKEND API
// ===================================
// Платформа для поиска потерянных и найденных питомцев
// Используется: Node.js, Express, MongoDB Atlas, JWT

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ===================================
// MIDDLEWARE
// ===================================
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:3000', 
    'http://127.0.0.1:5173',
    'http://127.0.0.1:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Добавьте логирование для отладки
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, {
    body: req.body,
    headers: req.headers
  });
  next();
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// Настройка загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Только изображения разрешены'));
  }
});

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/avatars'),
  filename: (req, file, cb) =>
    cb(null, `avatar-${req.user.userId}-${Date.now()}.png`)
});

const uploadAvatar = multer({
  storage: avatarStorage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Только изображения'));
  }
});

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ===================================
// EMAIL CONFIGURATION
// ===================================
const transporter = nodemailer.createTransport({
  service: 'gmail', // или другой сервис (smtp.mail.ru, яндекс и т.д.)
  auth: {
    user: process.env.EMAIL_USER, // ваш email
    pass: process.env.EMAIL_PASSWORD // пароль приложения (для Gmail - App Password)
  }
});

// Функция генерации 6-значного кода
const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Функция отправки email с кодом
const sendVerificationEmail = async (email, code, name) => {
  
  const mailOptions = {
    from: `"Pet Finder" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Подтверждение регистрации - Pet Finder',
    html: `
      <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #F9FFF8; border-radius: 12px; overflow: hidden; border: 1px solid #E6F4EA;">
        
      <div style="background-color: #DDF6E6; text-align: center; ; position: relative;">
  <img 
    src="https://images.unsplash.com/photo-1592194996308-7b43878e84a6?auto=format&fit=crop&w=1950&q=80" 
    alt="Pet Finder Logo" 
    style="width: 100%; height: 200px; object-fit: cover; border-radius: 12px 12px 0 0;"
  >
  <h2 style="color: #2F855A; margin: 15px 0 0 0; font-size: 28px; position: relative; z-index: 1;padding: 30px">
    Добро пожаловать в Pet Finder!
  </h2>
</div>

        <div style="padding: 30px;">
          <p style="font-size: 16px; color: #1A202C;">Здравствуйте, <strong>${name}</strong>!</p>
          <p style="font-size: 16px; color: #1A202C;">Спасибо за регистрацию на нашей платформе для поиска потерянных питомцев.</p>
          
          <p style="font-size: 16px; color: #1A202C;">Ваш код подтверждения:</p>
          <div style="background-color: #E6F4EA; padding: 25px; text-align: center; margin: 20px 0; border-radius: 10px;">
            <h1 style="color: #2F855A; margin: 0; font-size: 36px; letter-spacing: 5px;">${code}</h1>
          </div>
          <p style="font-size: 14px; color: #4A5568;">Код действителен в течение <strong>10 минут</strong>.</p>

          <p style="font-size: 14px; color: #4A5568;">Если вы не регистрировались на Pet Finder, просто проигнорируйте это письмо.</p>
        </div>

        <div style="text-align: center; padding: 20px; background-color: #DDF6E6;">
          <img src="https://i.imgur.com/Zqj0rTQ.jpg" alt="Cute pets" style="width: 100%; max-width: 500px; border-radius: 12px;">
        </div>

        <hr style="border: none; border-top: 1px solid #C6F0D6; margin: 30px 0;">

        <p style="color: #4A5568; font-size: 12px; text-align: center; margin-bottom: 20px;">
          С уважением,<br>
          Команда Pet Finder
        </p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Ошибка отправки email:', error);
    return false;
  }
};


// ===================================
// ПОДКЛЮЧЕНИЕ К MONGODB ATLAS
// ===================================
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ MongoDB Atlas подключен');
  })
  .catch((err) => {
    console.error('❌ Ошибка подключения к MongoDB:', err.message);
    process.exit(1);
  });

// ===================================
// MONGOOSE SCHEMAS & MODELS
// ===================================

const VerificationCodeSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true },
  code: { type: String, required: true },
  userData: {
    name: String,
    password: String,
    phone: String
  },
  createdAt: { type: Date, default: Date.now, expires: 600 }
});

const VerificationCode = mongoose.model('VerificationCode', VerificationCodeSchema);

// 1. Пользователь (расширяемый для волонтёров, админов, приютов)
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String },
  name: { type: String, required: true },
  phone: { type: String },

  role: {
    type: String,
    enum: ['user', 'volunteer', 'shelter', 'admin'],
    default: 'user'
  },

  authProvider: {
    type: String,
    enum: ['email', 'google', 'telegram'],
    default: 'email'
  },

  telegramId: String,
  googleId: String,
  avatar: {
    type: String,
    default: '/uploads/avatars/default.png'
  },

  volunteerInfo: {
    isActive: { type: Boolean, default: false },
    radius: { type: Number, default: 10 },
    animalTypes: [String]
  },

  shelterInfo: {
    name: String,
    address: String,
    description: String,
    capacity: Number,
    currentAnimals: Number,
    website: String
  },

  notificationSettings: {
    email: { type: Boolean, default: true },
    telegram: { type: Boolean, default: false },
    radius: { type: Number, default: 5 }
  }

}, { timestamps: true });

UserSchema.index({ 'location.coordinates': '2dsphere' });
const User = mongoose.model('User', UserSchema);

// 2. Объявление о питомце
const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['lost', 'found'], required: true },
  animalType: { type: String, required: true },
  name: { type: String },
  breed: { type: String },
  color: { type: String },
  age: { type: String },
  gender: { type: String, enum: ['male', 'female', 'unknown'] },
  description: { type: String, required: true },
  photos: [String],
  location: {
    city: { type: String, required: true },
    address: String,
    coordinates: {
      type: { type: String, enum: ['Point'], default: 'Point' },
      coordinates: { type: [Number], required: true }
    }
  },
  date: { type: Date, required: true },
  status: { 
    type: String, 
    enum: ['active', 'resolved', 'closed'], 
    default: 'active' 
  },
  contactInfo: {
    phone: String,
    preferredContact: { type: String, enum: ['phone', 'chat', 'both'], default: 'both' }
  },
  views: { type: Number, default: 0 },
  aiFeatures: {
    analyzed: { type: Boolean, default: false },
    features: mongoose.Schema.Types.Mixed
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

PostSchema.index({ 'location.coordinates': '2dsphere' });
PostSchema.index({ animalType: 1, status: 1 });
PostSchema.index({ createdAt: -1 });
const Post = mongoose.model('Post', PostSchema);

// 3. Чат между пользователями
const ChatSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  lastMessage: { type: String },
  lastMessageAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

ChatSchema.index({ participants: 1 });
const Chat = mongoose.model('Chat', ChatSchema);

// 4. Сообщения в чате
const MessageSchema = new mongoose.Schema({
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

MessageSchema.index({ chatId: 1, createdAt: -1 });
const Message = mongoose.model('Message', MessageSchema);

// 5. Уведомления
const NotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { 
    type: String, 
    enum: ['new_post_nearby', 'message', 'post_match', 'volunteer_alert', 'shelter_update'],
    required: true 
  },
  title: { type: String, required: true },
  message: { type: String, required: true },
  relatedPost: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  relatedChat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat' },
  read: { type: Boolean, default: false },
  sent: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

NotificationSchema.index({ userId: 1, read: 1 });
const Notification = mongoose.model('Notification', NotificationSchema);

// ===================================
// AUTH MIDDLEWARE
// ===================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Токен не предоставлен' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Невалидный токен' });
    req.user = user;
    next();
  });
};

const authorizeRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }
    next();
  };
};

// ===================================
// HELPER FUNCTIONS
// ===================================

const generateToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
};

const notifyNearbyUsers = async (post) => {
  try {
    const nearbyUsers = await User.find({
      'location.coordinates': {
        $near: {
          $geometry: post.location.coordinates,
          $maxDistance: 5000
        }
      },
      _id: { $ne: post.userId },
      'notificationSettings.email': true
    });

    for (const user of nearbyUsers) {
      await Notification.create({
        userId: user._id,
        type: 'new_post_nearby',
        title: `Новое объявление поблизости`,
        message: `${post.type === 'lost' ? 'Потерян' : 'Найден'} ${post.animalType} в ${post.location.city}`,
        relatedPost: post._id
      });
    }
  } catch (error) {
    console.error('Ошибка отправки уведомлений:', error);
  }
};

// ===================================
// API ROUTES
// ===================================

// ========== НОВАЯ СИСТЕМА РЕГИСТРАЦИИ С EMAIL ВЕРИФИКАЦИЕЙ ==========

// ШАГ 1: Отправка кода на email



app.post('/api/auth/register/send-code', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    console.log('SEND-CODE HIT', req.body);

    // Валидация данных
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Заполните все обязательные поля' });
    }

    // Проверка существующего пользователя
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Генерация кода
    const code = generateVerificationCode();

    // Удаление старых кодов для этого email
    await VerificationCode.deleteMany({ email });

    // Сохранение кода и данных пользователя
    await VerificationCode.create({
      email,
      code,
      userData: {
        name,
        password: hashedPassword,
        phone
      }
    });

    // Отправка email
    const emailSent = await sendVerificationEmail(email, code, name);

    if (!emailSent) {
      return res.status(500).json({ error: 'Ошибка отправки email' });
    }

    res.json({ 
      message: 'Код подтверждения отправлен на email',
      email // для удобства фронтенда
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка отправки кода', details: error.message });
  }
});

// ШАГ 2: Подтверждение кода и создание пользователя
app.post('/api/auth/register/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email и код обязательны' });
    }

    // Поиск кода
    const verificationRecord = await VerificationCode.findOne({ email, code });

    if (!verificationRecord) {
      return res.status(400).json({ error: 'Неверный или истёкший код' });
    }

    // Создание пользователя
    const user = await User.create({
      email,
      password: verificationRecord.userData.password,
      name: verificationRecord.userData.name,
      phone: verificationRecord.userData.phone,
      authProvider: 'email'
    });

    // Удаление кода после успешной регистрации
    await VerificationCode.deleteOne({ _id: verificationRecord._id });

    // Генерация токена
    const token = generateToken(user);

    res.status(201).json({
      message: 'Регистрация успешно завершена',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка подтверждения кода', details: error.message });
  }
});

// ШАГ 3: Повторная отправка кода (опционально)
app.post('/api/auth/register/resend-code', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email обязателен' });
    }

    // Поиск существующего кода
    const verificationRecord = await VerificationCode.findOne({ email });

    if (!verificationRecord) {
      return res.status(404).json({ error: 'Код не найден. Начните регистрацию заново' });
    }

    // Генерация нового кода
    const newCode = generateVerificationCode();
    verificationRecord.code = newCode;
    verificationRecord.createdAt = Date.now();
    await verificationRecord.save();

    // Отправка email
    const emailSent = await sendVerificationEmail(
      email, 
      newCode, 
      verificationRecord.userData.name
    );

    if (!emailSent) {
      return res.status(500).json({ error: 'Ошибка отправки email' });
    }

    res.json({ message: 'Новый код отправлен на email' });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка повторной отправки', details: error.message });
  }
});

// ========== СТАРАЯ РЕГИСТРАЦИЯ (оставлена для обратной совместимости) ==========
// Можно удалить, если не нужна
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      password: hashedPassword,
      name,
      phone,
      authProvider: 'email'
    });

    const token = generateToken(user);

    res.status(201).json({
      message: 'Пользователь успешно зарегистрирован',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка регистрации', details: error.message });
  }
});

// ========== АУТЕНТИФИКАЦИЯ ==========

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    const token = generateToken(user);

    res.json({
      message: 'Успешный вход',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка входа', details: error.message });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { tokenId } = req.body;

    const ticket = await googleClient.verifyIdToken({
      idToken: tokenId,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const { email, name, sub: googleId, picture } = ticket.getPayload();

    let user = await User.findOne({ email });
    
    if (!user) {
      user = await User.create({
        email,
        name,
        googleId,
        avatar: picture,
        authProvider: 'google'
      });
    }

    const token = generateToken(user);

    res.json({
      message: 'Успешный вход через Google',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка Google авторизации', details: error.message });
  }
});

app.post('/api/auth/telegram', async (req, res) => {
  try {
    const { telegramId, firstName, lastName, username } = req.body;

    let user = await User.findOne({ telegramId });
    
    if (!user) {
      user = await User.create({
        email: `telegram_${telegramId}@petfinder.com`,
        name: `${firstName} ${lastName || ''}`.trim() || username,
        telegramId,
        authProvider: 'telegram'
      });
    }

    const token = generateToken(user);

    res.json({
      message: 'Успешный вход через Telegram',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка Telegram авторизации', details: error.message });
  }
});

// ========== ПОЛЬЗОВАТЕЛИ ==========

app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения профиля' });
  }
});

app.post(
  '/api/users/me/avatar',
  authenticateToken,
  uploadAvatar.single('avatar'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'Файл не загружен' });
      }

      const avatarPath = `/uploads/avatars/${req.file.filename}`;

      const user = await User.findByIdAndUpdate(
        req.user.userId,
        { avatar: avatarPath },
        { new: true }
      ).select('-password');

      res.json({
        message: 'Аватарка обновлена',
        avatar: avatarPath,
        user
      });
    } catch (error) {
      res.status(500).json({ error: 'Ошибка загрузки аватарки' });
    }
  }
);

app.put('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    delete updates.password;
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { ...updates, updatedAt: Date.now() },
      { new: true }
    ).select('-password');

    res.json({ message: 'Профиль обновлён', user });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка обновления профиля' });
  }
});

app.get('/api/users/me/posts', authenticateToken, async (req, res) => {
  try {
    const posts = await Post.find({ userId: req.user.userId })
      .sort({ createdAt: -1 });
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения объявлений' });
  }
});

app.post('/api/users/me/volunteer', authenticateToken, async (req, res) => {
  try {
    const { radius, animalTypes } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      {
        role: 'volunteer',
        'volunteerInfo.isActive': true,
        'volunteerInfo.radius': radius || 10,
        'volunteerInfo.animalTypes': animalTypes || []
      },
      { new: true }
    ).select('-password');

    res.json({ message: 'Вы стали волонтёром', user });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка регистрации волонтёра' });
  }
});

// ========== ОБЪЯВЛЕНИЯ ==========

app.post('/api/posts', authenticateToken, upload.array('photos', 5), async (req, res) => {
  try {
    const { type, animalType, name, breed, color, age, gender, description, 
            city, address, longitude, latitude, date, phone } = req.body;

    const photos = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];

    const post = await Post.create({
      userId: req.user.userId,
      type,
      animalType,
      name,
      breed,
      color,
      age,
      gender,
      description,
      photos,
      location: {
        city,
        address,
        coordinates: {
          type: 'Point',
          coordinates: [parseFloat(longitude), parseFloat(latitude)]
        }
      },
      date: date || Date.now(),
      contactInfo: {
        phone,
        preferredContact: 'both'
      }
    });

    await notifyNearbyUsers(post);

    res.status(201).json({ message: 'Объявление создано', post });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка создания объявления', details: error.message });
  }
});

app.get('/api/posts', async (req, res) => {
  try {
    const { 
      type, animalType, city, status = 'active',
      latitude, longitude, radius = 10,
      page = 1, limit = 20 
    } = req.query;

    let query = { status };

    if (type) query.type = type;
    if (animalType) query.animalType = animalType;
    if (city) query['location.city'] = new RegExp(city, 'i');

    if (latitude && longitude) {
      query['location.coordinates'] = {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(longitude), parseFloat(latitude)]
          },
          $maxDistance: radius * 1000
        }
      };
    }

    const posts = await Post.find(query)
      .populate('userId', 'name phone avatar')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await Post.countDocuments(query);

    res.json({
      posts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения объявлений', details: error.message });
  }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await Post.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true }
    ).populate('userId', 'name phone avatar');

    if (!post) {
      return res.status(404).json({ error: 'Объявление не найдено' });
    }

    res.json(post);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения объявления' });
  }
});

app.put('/api/posts/:id', authenticateToken, upload.array('photos', 5), async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ error: 'Объявление не найдено' });
    }

    if (post.userId.toString() !== req.user.userId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }

    const updates = { ...req.body, updatedAt: Date.now() };
    
    if (req.files && req.files.length > 0) {
      const newPhotos = req.files.map(file => `/uploads/${file.filename}`);
      updates.photos = [...(post.photos || []), ...newPhotos];
    }

    const updatedPost = await Post.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    );

    res.json({ message: 'Объявление обновлено', post: updatedPost });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка обновления объявления' });
  }
});

app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ error: 'Объявление не найдено' });
    }

    if (post.userId.toString() !== req.user.userId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }

    await Post.findByIdAndDelete(req.params.id);
    res.json({ message: 'Объявление удалено' });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка удаления объявления' });
  }
});

app.patch('/api/posts/:id/resolve', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ error: 'Объявление не найдено' });
    }

    if (post.userId.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }

    post.status = 'resolved';
    await post.save();

    res.json({ message: 'Объявление закрыто', post });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка закрытия объявления' });
  }
});

// ========== ЧАТЫ ==========

app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { userId, postId } = req.body;
    
    let chat = await Chat.findOne({
      participants: { $all: [req.user.userId, userId] },
      postId
    });

    if (!chat) {
      chat = await Chat.create({
        participants: [req.user.userId, userId],
        postId
      });
    }

    res.json(chat);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка создания чата' });
  }
});

app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({
      participants: req.user.userId
    })
    .populate('participants', 'name avatar')
    .populate('postId', 'type animalType photos')
    .sort({ lastMessageAt: -1 });

    res.json(chats);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения чатов' });
  }
});

app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;

    const chat = await Chat.findById(req.params.chatId);
    if (!chat || !chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }

    const messages = await Message.find({ chatId: req.params.chatId })
      .populate('senderId', 'name avatar')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    res.json(messages.reverse());
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения сообщений' });
  }
});

app.post('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;

    const chat = await Chat.findById(req.params.chatId);
    if (!chat || !chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }

    const message = await Message.create({
      chatId: req.params.chatId,
      senderId: req.user.userId,
      text
    });

    await Chat.findByIdAndUpdate(req.params.chatId, {
      lastMessage: text,
      lastMessageAt: Date.now()
    });

    const recipientId = chat.participants.find(id => id.toString() !== req.user.userId);
    await Notification.create({
      userId: recipientId,
      type: 'message',
      title: 'Новое сообщение',
      message: text.substring(0, 50),
      relatedChat: chat._id
    });

    res.status(201).json(message);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка отправки сообщения' });
  }
});

// ========== УВЕДОМЛЕНИЯ ==========

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user.userId })
      .populate('relatedPost', 'type animalType photos')
      .sort({ createdAt: -1 })
      .limit(50);

    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения уведомлений' });
  }
});

app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    await Notification.findByIdAndUpdate(req.params.id, { read: true });
    res.json({ message: 'Уведомление прочитано' });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка обновления уведомления' });
  }
});

// ========== АДМИН-ПАНЕЛЬ ==========

app.get('/api/admin/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 20, role } = req.query;

    let query = {};
    if (role) query.role = role;

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await User.countDocuments(query);

    res.json({
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения пользователей' });
  }
});

app.listen(PORT, () => {
  console.log(`
🚀 Pet Finder API запущен
🌍 http://localhost:${PORT}
📦 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}
📧 Email верификация: ${process.env.EMAIL_USER ? '✅ Настроена' : '❌ Не настроена'}
  `);
});