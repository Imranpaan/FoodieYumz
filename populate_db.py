from main import db, Restaurant, app

def add_restaurants():
    with app.app_context():
        restaurants = [
            Restaurant(name='Deen\'s Cafe', description='A cozy cafe with a variety of food options.', image='static/images/deens_cafe.jpg'),
            Restaurant(name='Haji Tapah Cafe', description='Famous for its traditional dishes and snacks.', image='static/images/haji_tapah_cafe.jpg'),
            Restaurant(name='Starbees', description='A modern cafe known for its coffee and pastries.', image='static/images/starbees.jpg')
        ]
        
        db.session.add_all(restaurants)
        db.session.commit()

if __name__ == '__main__':
    add_restaurants()
