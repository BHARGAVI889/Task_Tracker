// server.js
// Complete backend: auth (register/login), tasks, habits, stats.
// In-memory storage (data resets when the server restarts) - no database setup needed.

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'task-habit-tracker-secret-key';// fine for local/student projects
const JWT_EXPIRES_IN = '7d'; // long-lived so it won't randomly "expire" while you're working

// ---------- IN-MEMORY DATA ----------
let users = [];      // { id, username, email, passwordHash }
let tasks = [];       // { id, userId, title, dueDate, priority, status }
let habits = [];      // { id, userId, name, frequency, streak }
let nextId = 1;
function genId() { return String(nextId++); }

// ---------- AUTH MIDDLEWARE ----------
function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

// ---------- AUTH ROUTES ----------
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required.' });
  }
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'An account with that email already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: genId(), username, email, passwordHash };
  users.push(user);

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ error: 'Invalid email or password.' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(400).json({ error: 'Invalid email or password.' });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

// ---------- TASK ROUTES ----------
app.get('/api/tasks', requireAuth, (req, res) => {
  res.json(tasks.filter(t => t.userId === req.userId));
});

app.post('/api/tasks', requireAuth, (req, res) => {
  const { title, description, dueDate, priority, status } = req.body || {};
  if (!title) return res.status(400).json({ error: 'Title is required.' });

  const task = {
    id: genId(),
    userId: req.userId,
    title,
    description: description || '',
    dueDate: dueDate || null,
    priority: priority || 'medium',
    status: status || 'pending',
    completed: (status || 'pending') === 'completed',
  };
  tasks.push(task);
  res.status(201).json(task);
});

app.put('/api/tasks/:id', requireAuth, (req, res) => {
  const task = tasks.find(t => t.id === req.params.id && t.userId === req.userId);
  if (!task) return res.status(404).json({ error: 'Task not found.' });

  Object.assign(task, req.body);
  if (req.body.completed !== undefined) {
    task.status = req.body.completed ? 'completed' : 'pending';
  }
  if (req.body.status !== undefined) {
    task.completed = req.body.status === 'completed';
  }
  res.json(task);
});

app.delete('/api/tasks/:id', requireAuth, (req, res) => {
  const before = tasks.length;
  tasks = tasks.filter(t => !(t.id === req.params.id && t.userId === req.userId));
  if (tasks.length === before) return res.status(404).json({ error: 'Task not found.' });
  res.json({ success: true });
});

// ---------- HABIT ROUTES ----------
app.get('/api/habits', requireAuth, (req, res) => {
  res.json(habits.filter(h => h.userId === req.userId));
});

app.post('/api/habits', requireAuth, (req, res) => {
  const { name, frequency } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Habit name is required.' });

  const habit = {
    id: genId(),
    userId: req.userId,
    name,
    frequency: frequency || 'daily',
    streak: 0,
  };
  habits.push(habit);
  res.status(201).json(habit);
});

app.post('/api/habits/:id/checkin', requireAuth, (req, res) => {
  const habit = habits.find(h => h.id === req.params.id && h.userId === req.userId);
  if (!habit) return res.status(404).json({ error: 'Habit not found.' });
  habit.streak += 1;
  res.json(habit);
});
// alias so either route name works
app.post('/api/habits/:id/log', requireAuth, (req, res) => {
  const habit = habits.find(h => h.id === req.params.id && h.userId === req.userId);
  if (!habit) return res.status(404).json({ error: 'Habit not found.' });
  habit.streak += 1;
  res.json(habit);
});

app.delete('/api/habits/:id', requireAuth, (req, res) => {
  const before = habits.length;
  habits = habits.filter(h => !(h.id === req.params.id && h.userId === req.userId));
  if (habits.length === before) return res.status(404).json({ error: 'Habit not found.' });
  res.json({ success: true });
});

// ---------- STATS ----------
app.get('/api/stats', requireAuth, (req, res) => {
  const myTasks = tasks.filter(t => t.userId === req.userId);
  const myHabits = habits.filter(h => h.userId === req.userId);

  res.json({
    openTasks: myTasks.filter(t => t.status !== 'completed').length,
    completedTasks: myTasks.filter(t => t.status === 'completed').length,
    totalHabits: myHabits.length,
    bestStreak: myHabits.reduce((max, h) => Math.max(max, h.streak || 0), 0),
  });
});

app.listen(process.env.PORT || 5000, () => {
  console.log("Server running");
});
