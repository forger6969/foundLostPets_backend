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

const app = express();
const PORT = process.env.PORT || 3000;

// ===================================
// MIDDLEWARE
// ===================================
app.use(cors());
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
// ПОДКЛЮЧЕНИЕ К MONGODB ATLAS
// ===================================
// ===================================
// ПОДКЛЮЧЕНИЕ К MONGODB ATLAS (FIXED)
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


// Индексы для геолокации
UserSchema.index({ 'location.coordinates': '2dsphere' });

const User = mongoose.model('User', UserSchema);

// 2. Объявление о питомце
const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['lost', 'found'], required: true }, // Потерял / Нашёл
  animalType: { type: String, required: true }, // собака, кошка, птица и т.д.
  name: { type: String }, // Имя питомца (может быть неизвестно для найденных)
  breed: { type: String },
  color: { type: String },
  age: { type: String },
  gender: { type: String, enum: ['male', 'female', 'unknown'] },
  description: { type: String, required: true },
  photos: [String], // URLs фотографий
  location: {
    city: { type: String, required: true },
    address: String,
    coordinates: {
      type: { type: String, enum: ['Point'], default: 'Point' },
      coordinates: { type: [Number], required: true } // [longitude, latitude]
    }
  },
  date: { type: Date, required: true }, // Дата потери/находки
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
  // Для будущей интеграции AI поиска по фото
  aiFeatures: {
    analyzed: { type: Boolean, default: false },
    features: mongoose.Schema.Types.Mixed
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Индексы для быстрого поиска
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

// Middleware для проверки роли
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

// Генерация JWT токена
const generateToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
};

// Отправка уведомлений пользователям поблизости
const notifyNearbyUsers = async (post) => {
  try {
    const nearbyUsers = await User.find({
      'location.coordinates': {
        $near: {
          $geometry: post.location.coordinates,
          $maxDistance: 5000 // 5 км
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

// ========== АУТЕНТИФИКАЦИЯ ==========

// Регистрация через Email
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;

    // Проверка существующего пользователя
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Создание пользователя
    const user = await User.create({
      email,
      password: hashedPassword,
      name,
      phone,
      authProvider: 'email'
    });

    // Генерация токена
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

// Вход через Email
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Поиск пользователя
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // Проверка пароля
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // Генерация токена
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

// Вход через Google
app.post('/api/auth/google', async (req, res) => {
  try {
    const { tokenId } = req.body;

    // Верификация Google токена
    const ticket = await googleClient.verifyIdToken({
      idToken: tokenId,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const { email, name, sub: googleId, picture } = ticket.getPayload();

    // Поиск или создание пользователя
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

// Вход через Telegram (webhook от Telegram бота)
app.post('/api/auth/telegram', async (req, res) => {
  try {
    const { telegramId, firstName, lastName, username } = req.body;

    // Поиск или создание пользователя
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

// Получить текущего пользователя
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


// Обновить профиль
app.put('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    delete updates.password; // Пароль обновляется отдельно
    
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

// Получить объявления пользователя
app.get('/api/users/me/posts', authenticateToken, async (req, res) => {
  try {
    const posts = await Post.find({ userId: req.user.userId })
      .sort({ createdAt: -1 });
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения объявлений' });
  }
});

// Стать волонтёром
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

// Создать объявление
app.post('/api/posts', authenticateToken, upload.array('photos', 5), async (req, res) => {
  try {
    const { type, animalType, name, breed, color, age, gender, description, 
            city, address, longitude, latitude, date, phone } = req.body;

    // Обработка загруженных фото
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

    // Уведомление пользователей поблизости
    await notifyNearbyUsers(post);

    res.status(201).json({ message: 'Объявление создано', post });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка создания объявления', details: error.message });
  }
});

// Получить все объявления с фильтрами
app.get('/api/posts', async (req, res) => {
  try {
    const { 
      type, animalType, city, status = 'active',
      latitude, longitude, radius = 10, // радиус в км
      page = 1, limit = 20 
    } = req.query;

    let query = { status };

    // Фильтры
    if (type) query.type = type;
    if (animalType) query.animalType = animalType;
    if (city) query['location.city'] = new RegExp(city, 'i');

    // Геолокационный поиск
    if (latitude && longitude) {
      query['location.coordinates'] = {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(longitude), parseFloat(latitude)]
          },
          $maxDistance: radius * 1000 // км в метры
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

// Получить объявление по ID
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

// Обновить объявление
app.put('/api/posts/:id', authenticateToken, upload.array('photos', 5), async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ error: 'Объявление не найдено' });
    }

    // Проверка владельца
    if (post.userId.toString() !== req.user.userId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }

    const updates = { ...req.body, updatedAt: Date.now() };
    
    // Обработка новых фото
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

// Удалить объявление
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

// Закрыть объявление (питомец найден)
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

// Создать или получить чат с пользователем
app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { userId, postId } = req.body;
    
    // Проверка существующего чата
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

// Получить все чаты пользователя
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

// Получить сообщения чата
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;

    // Проверка доступа к чату
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

// Отправить сообщение
app.post('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;

    // Проверка доступа к чату
    const chat = await Chat.findById(req.params.chatId);
    if (!chat || !chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }

    const message = await Message.create({
      chatId: req.params.chatId,
      senderId: req.user.userId,
      text
    });

    // Обновление последнего сообщения в чате
    await Chat.findByIdAndUpdate(req.params.chatId, {
      lastMessage: text,
      lastMessageAt: Date.now()
    });

    // Создание уведомления для получателя
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

// Получить уведомления
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

// Отметить уведомление как прочитанное
app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    await Notification.findByIdAndUpdate(req.params.id, { read: true });
    res.json({ message: 'Уведомление прочитано' });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка обновления уведомления' });
  }
});

// ========== АДМИН-ПАНЕЛЬ ==========

// Получить всех пользователей (админ)
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
  `);
});
