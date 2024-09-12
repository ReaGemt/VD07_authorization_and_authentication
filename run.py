from app import db, create_app

app = create_app()

# Создание всех таблиц при первом запуске
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
