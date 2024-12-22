import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import hashlib

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Fitness Tracker - Login")
        self.root.geometry("300x250")
        
        # Initialize database
        self.init_database()
        
        # Login Frame
        self.login_frame = ttk.Frame(root, padding="20")
        self.login_frame.pack(fill='both', expand=True)
        
        # Username
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.pack(pady=5)
        
        # Password
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=5)
        
        # Login Button
        ttk.Button(self.login_frame, text="Login", command=self.login).pack(pady=10)
        
        # Register Button
        ttk.Button(self.login_frame, text="Register", command=self.show_register).pack(pady=5)

    def init_database(self):
        self.conn = sqlite3.connect('fitness_tracker.db')
        self.cursor = self.conn.cursor()

        
        self.cursor.execute('DROP TABLE IF EXISTS workouts')
        self.cursor.execute('DROP TABLE IF EXISTS users')
        
        # Create users table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # Modify workouts table to include user_id
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS workouts (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                exercise_type TEXT NOT NULL,
                duration INTEGER NOT NULL,
                calories INTEGER NOT NULL,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        self.conn.commit()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def login(self):
        username = self.username_entry.get()
        password = self.hash_password(self.password_entry.get())
        
        self.cursor.execute('SELECT id FROM users WHERE username=? AND password=?', 
                          (username, password))
        user = self.cursor.fetchone()
        
        if user:
            self.root.withdraw()  # Hide login window
            app_window = tk.Toplevel()
            FitnessTrackerApp(app_window, user[0], self.root)  # Pass user_id and login window
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def show_register(self):
        register_window = tk.Toplevel(self.root)
        RegisterWindow(register_window, self.cursor, self.conn)

class RegisterWindow:
    def __init__(self, root, cursor, conn):
        self.root = root
        self.cursor = cursor
        self.conn = conn
        
        self.root.title("Register")
        self.root.geometry("300x250")
        
        # Register Frame
        register_frame = ttk.Frame(root, padding="20")
        register_frame.pack(fill='both', expand=True)
        
        # Username
        ttk.Label(register_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(register_frame)
        self.username_entry.pack(pady=5)
        
        # Password
        ttk.Label(register_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(register_frame, show="*")
        self.password_entry.pack(pady=5)
        
        # Confirm Password
        ttk.Label(register_frame, text="Confirm Password:").pack(pady=5)
        self.confirm_password_entry = ttk.Entry(register_frame, show="*")
        self.confirm_password_entry.pack(pady=5)
        
        # Register Button
        ttk.Button(register_frame, text="Register", command=self.register).pack(pady=10)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill all fields")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                              (username, hashed_password))
            self.conn.commit()
            messagebox.showinfo("Success", "Registration successful!")
            self.root.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")

class FitnessTrackerApp:
    def __init__(self, root, user_id, login_window):
        self.root = root
        self.user_id = user_id
        self.login_window = login_window
        
        self.root.title("Fitness Tracker")
        self.root.geometry("800x600")
        
        # Initialize database connection
        self.conn = sqlite3.connect('fitness_tracker.db')
        self.cursor = self.conn.cursor()
        
        # Create tabs
        self.tab_control = ttk.Notebook(root)
        
        # Add Workout Tab
        self.add_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.add_tab, text='Add Workout')
        self.setup_add_workout_tab()
        
        # View History Tab
        self.history_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.history_tab, text='History')
        self.setup_history_tab()
        
        # Statistics Tab
        self.stats_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.stats_tab, text='Statistics')
        self.setup_statistics_tab()
        
        self.tab_control.pack(expand=1, fill="both")
        
        # Add Logout Button
        ttk.Button(root, text="Logout", command=self.logout).pack(pady=5)
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_add_workout_tab(self):
        # Similar to previous implementation but modified for user_id
        ttk.Label(self.add_tab, text="Date (YYYY-MM-DD):").grid(row=0, column=0, padx=5, pady=5)
        self.date_entry = ttk.Entry(self.add_tab)
        self.date_entry.insert(0, datetime.now().strftime('%Y-%m-%d'))
        self.date_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.add_tab, text="Exercise Type:").grid(row=1, column=0, padx=5, pady=5)
        self.exercise_types = ['Running', 'Walking', 'Cycling', 'Swimming', 'Weight Training', 'Yoga', 'Other']
        self.exercise_type = ttk.Combobox(self.add_tab, values=self.exercise_types)
        self.exercise_type.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.add_tab, text="Duration (minutes):").grid(row=2, column=0, padx=5, pady=5)
        self.duration_entry = ttk.Entry(self.add_tab)
        self.duration_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(self.add_tab, text="Calories Burned:").grid(row=3, column=0, padx=5, pady=5)
        self.calories_entry = ttk.Entry(self.add_tab)
        self.calories_entry.grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(self.add_tab, text="Notes:").grid(row=4, column=0, padx=5, pady=5)
        self.notes_text = tk.Text(self.add_tab, height=4, width=30)
        self.notes_text.grid(row=4, column=1, padx=5, pady=5)

        submit_btn = ttk.Button(self.add_tab, text="Add Workout", command=self.add_workout)
        submit_btn.grid(row=5, column=0, columnspan=2, pady=20)

    def add_workout(self):
        try:
            date = self.date_entry.get()
            exercise = self.exercise_type.get()
            duration = int(self.duration_entry.get())
            calories = int(self.calories_entry.get())
            notes = self.notes_text.get("1.0", tk.END).strip()
            
            # Include user_id in workout entry
            self.cursor.execute('''
                INSERT INTO workouts (user_id, date, exercise_type, duration, calories, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (self.user_id, date, exercise, duration, calories, notes))
            self.conn.commit()
            
            # Clear entries
            self.duration_entry.delete(0, tk.END)
            self.calories_entry.delete(0, tk.END)
            self.notes_text.delete("1.0", tk.END)
            
            messagebox.showinfo("Success", "Workout added successfully!")
            self.refresh_history()
            
        except ValueError:
            messagebox.showerror("Error", "Please enter valid values!")

    def setup_history_tab(self):
        # Create Treeview
        self.tree = ttk.Treeview(self.history_tab, 
                                columns=('Date', 'Exercise', 'Duration', 'Calories', 'Notes'),
                                show='headings')
        
        # Set column headings
        self.tree.heading('Date', text='Date')
        self.tree.heading('Exercise', text='Exercise')
        self.tree.heading('Duration', text='Duration (min)')
        self.tree.heading('Calories', text='Calories')
        self.tree.heading('Notes', text='Notes')
        
        # Set column widths
        self.tree.column('Date', width=100)
        self.tree.column('Exercise', width=100)
        self.tree.column('Duration', width=100)
        self.tree.column('Calories', width=100)
        self.tree.column('Notes', width=200)
        
        self.tree.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Refresh button
        refresh_btn = ttk.Button(self.history_tab, text="Refresh", command=self.refresh_history)
        refresh_btn.pack(pady=10)
        
        # Initial load of data
        self.refresh_history()

    def refresh_history(self):
        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Fetch and insert data for current user
        self.cursor.execute('''
            SELECT date, exercise_type, duration, calories, notes 
            FROM workouts 
            WHERE user_id = ?
            ORDER BY date DESC
        ''', (self.user_id,))
        
        for row in self.cursor.fetchall():
            self.tree.insert('', 'end', values=row)

    def setup_statistics_tab(self):
        # Create Figure for matplotlib
        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.stats_tab)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add buttons for different charts
        ttk.Button(self.stats_tab, text="Weekly Summary", 
                  command=lambda: self.update_chart('weekly')).pack(pady=5)
        ttk.Button(self.stats_tab, text="Exercise Distribution", 
                  command=lambda: self.update_chart('distribution')).pack(pady=5)

    def update_chart(self, chart_type):
        self.ax.clear()
        
        if chart_type == 'weekly':
            self.cursor.execute('''
                SELECT date, SUM(calories) 
                FROM workouts 
                WHERE user_id = ?
                GROUP BY date 
                ORDER BY date DESC 
                LIMIT 7
            ''', (self.user_id,))
            data = self.cursor.fetchall()
            dates = [row[0] for row in data]
            calories = [row[1] for row in data]
            
            self.ax.bar(dates, calories)
            self.ax.set_title('Weekly Calories Burned')
            self.ax.set_xlabel('Date')
            self.ax.set_ylabel('Calories')
            plt.xticks(rotation=45)
            
        elif chart_type == 'distribution':
            self.cursor.execute('''
                SELECT exercise_type, COUNT(*) 
                FROM workouts 
                WHERE user_id = ?
                GROUP BY exercise_type
            ''', (self.user_id,))
            data = self.cursor.fetchall()
            exercises = [row[0] for row in data]
            counts = [row[1] for row in data]
            
            self.ax.pie(counts, labels=exercises, autopct='%1.1f%%')
            self.ax.set_title('Exercise Type Distribution')
        
        self.fig.tight_layout()
        self.canvas.draw()

    def logout(self):
        self.root.destroy()
        self.login_window.deiconify()  # Show login window again

    def on_closing(self):
        self.root.destroy()
        self.login_window.destroy()

def main():
    root = tk.Tk()
    login = LoginWindow(root)
    root.mainloop()
    print('Welcome to Fitness Tracker!')

if __name__ == "__main__":
    main()
