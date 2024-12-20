from flask import Flask, request, jsonify, render_template, session, redirect, url_for,flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash  # for checking hashed passwords

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = ''
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

# Define the database models

class User(db.Model):
    __tablename__ = 'Users'
    
    user_id = db.Column(db.String(255), primary_key=True)
    user_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255))
    email = db.Column(db.String(255))
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(255))  # Ensure this is added
    updated_by = db.Column(db.String(255))  # Ensure this is added
    
    def __repr__(self):
        return f"User({self.user_name}, {self.email})"


class UGroup(db.Model):
    __tablename__ = 'UGroups'
    group_id = db.Column(db.String(255), primary_key=True)
    group_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    
    # Relationship to UserGroups
    user_groups = db.relationship('UserGroup', backref='group_backref', lazy=True)
    

class Module(db.Model):
    __tablename__ = 'Modules'
    module_id = db.Column(db.String(255), primary_key=True)
    module_name = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    description = db.Column(db.String(255))

class Permission(db.Model):
    __tablename__ = 'Permissions'
    permission_id = db.Column(db.String(255), primary_key=True)
    action = db.Column(db.String(255), nullable=False)
    level = db.Column(db.String(255), default='user')
    description = db.Column(db.String(255))
    is_default = db.Column(db.Boolean, default=False)


class GroupModulePermission(db.Model):
    __tablename__ = 'GroupModulePermissions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    group_id = db.Column(db.String(255), db.ForeignKey('UGroups.group_id'))
    module_id = db.Column(db.String(255), db.ForeignKey('Modules.module_id'))
    permission_id = db.Column(db.String(255), db.ForeignKey('Permissions.permission_id'))
    priority = db.Column(db.Integer)
    
    # Relationships
    group = db.relationship('UGroup', backref='group_module_permissions')
    module = db.relationship('Module', backref='group_module_permissions')
    permission = db.relationship('Permission', backref='group_module_permissions')

class UserGroup(db.Model):
    __tablename__ = 'UserGroups'

    usergroup_id = db.Column(db.String(255), primary_key=True)
    user_id = db.Column(db.String(255), db.ForeignKey('Users.user_id'), nullable=False)
    group_id = db.Column(db.String(255), db.ForeignKey('UGroups.group_id'), nullable=False)
    assigned_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(255))
    updated_by = db.Column(db.String(255))

    # Relationships
    user = db.relationship('User', backref=db.backref('user_backref', lazy=True))  
    group = db.relationship('UGroup', backref=db.backref('group_backref', lazy=True))  

    __table_args__ = (
        db.Index('ix_user_id', 'user_id'),
        db.Index('ix_group_id', 'group_id'),
    )

    def __repr__(self):
        return f"UserGroup({self.usergroup_id}, {self.user_id}, {self.group_id})"

    
class Customer(db.Model):
    __tablename__ = 'customers'

    customer_id = db.Column(db.String(255), primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    phone = db.Column(db.String(255))
    address = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"Customer({self.first_name} {self.last_name}, {self.email})"

    
class SalesOrder(db.Model):
    __tablename__ = 'sales_orders'

    order_id = db.Column(db.String(255), primary_key=True)
    customer_id = db.Column(db.String(255), db.ForeignKey('customers.customer_id'), nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(255), default='Pending')  # Status of the order (e.g., Pending, Shipped)
    total_amount = db.Column(db.Float)
    
    # Relationship to Customer
    customer = db.relationship('Customer', backref=db.backref('sales_orders', lazy=True))

    def __repr__(self):
        return f"SalesOrder({self.order_id}, {self.customer_id}, {self.total_amount})"

# Create the database tables
with app.app_context():
    try:
        db.create_all()  # This will create all tables based on the defined models
        print("Tables created successfully!")
    except Exception as e:
        print(f"Error creating tables: {e}")

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    user_name = request.form['username']
    password = request.form['password']
    
    # Check if the user exists
    user = User.query.filter_by(user_name=user_name).first()
    
    if user and user.password == password:  # Direct comparison of plain text password
        # Fetch the user's group
        user_group = UserGroup.query.filter_by(user_id=user.user_id).first()
        if user_group:
            group = UGroup.query.filter_by(group_id=user_group.group_id).first()

            # Fetch associated modules and permissions for the group
            group_modules_permissions = db.session.query(GroupModulePermission, Module, Permission) \
                .join(Module, GroupModulePermission.module_id == Module.module_id) \
                .join(Permission, GroupModulePermission.permission_id == Permission.permission_id) \
                .filter(GroupModulePermission.group_id == group.group_id).all()

            # Store user and permissions in the session
            permissions = {}
            for gm, module, permission in group_modules_permissions:
                if module.module_name not in permissions:
                    permissions[module.module_name] = []
                permissions[module.module_name].append(permission.action)

            session['user'] = user.user_name
            session['group'] = group.group_name
            session['permissions'] = permissions  # Store permissions in session
            print(session['user'])
            print(session['group'])
            print(session['permissions'])
            return render_template('dashboard.html', user=user, group=group, modules_permissions=permissions)
        else:
            flash("No group assigned to user.", 'danger')
            return redirect(url_for('index'))
    else:
        flash("Invalid username or password.", 'danger')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    # Ensure the user is logged in and has permission
    if 'user' not in session:
        flash("You must be logged in to view this page.", 'danger')
        return redirect(url_for('index'))  # Redirect to the login page if the user is not logged in

    # Fetch the logged-in user from the session
    user_name = session.get('user')
    group_name = session.get('group')
    permissions = session.get('permissions')

    # Fetch customers from the database to display on the dashboard
    customers = Customer.query.all()  # This can be adjusted depending on what you want to show

    # Render the dashboard template, passing user data, group, permissions, and customers
    return render_template('dashboard.html', user=user_name, group=group_name, modules_permissions=permissions, customers=customers)

@app.route('/user_management')
def user_management():
    # This route will render the User Management page
    return render_template('user_management.html')

@app.route('/customer_management')
def customer_management():
    # This route will render the Customer Management page
    return render_template('customer_management.html')

@app.route('/sales_management')
def sales_management():
    # This route will render the Sales Management page
    return render_template('sales_management.html')

@app.route('/view_modules_permissions')
def view_modules_permissions():
    # Assuming you are storing modules and permissions in the session
    if 'user' in session:
        # Fetch the user using the session's user_name
        user = User.query.filter_by(user_name=session['user']).first()
        if user:
            # Fetch the user's group
            user_group = UserGroup.query.filter_by(user_id=user.user_id).first()
            if user_group:
                group = UGroup.query.filter_by(group_id=user_group.group_id).first()

                # Fetch associated modules and permissions for the user's group
                group_modules_permissions = db.session.query(GroupModulePermission, Module, Permission) \
                    .join(Module, GroupModulePermission.module_id == Module.module_id) \
                    .join(Permission, GroupModulePermission.permission_id == Permission.permission_id) \
                    .filter(GroupModulePermission.group_id == group.group_id).all()

                # Prepare a structure for passing to the template
                modules_permissions = {}
                for gm, module, permission in group_modules_permissions:
                    if module.module_name not in modules_permissions:
                        modules_permissions[module.module_name] = []
                    modules_permissions[module.module_name].append(permission.action)

                return render_template('view_modules_permissions.html', modules_permissions=modules_permissions)
            else:
                flash("No group found for the user.", 'danger')
                return redirect(url_for('dashboard'))
        else:
            flash("User not found.", 'danger')
            return redirect(url_for('login'))
    else:
        flash("User not logged in.", 'danger')
        return redirect(url_for('login'))



@app.route('/view_users')
def view_users():
    # Check if user has 'View Users' permission
    if 'View Users' in session['permissions'].get('User Management', []):
        users = User.query.all()  # Fetch all users from the database
        return render_template('view_users.html', users=users)
    else:
        # If the user doesn't have permission, redirect or show a flash message
        flash("You do not have permission to view users.", 'danger')
        return redirect(url_for('dashboard'))


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'Add User' in session['permissions'].get('User Management', []):
        if request.method == 'POST':
            user_name = request.form['username']
            password = request.form['password']
            role = request.form['role']
            email = request.form['email']

            # Get the logged-in user's username (or user ID)
            current_user = session.get('user')  # Assuming 'user' is the logged-in username in session

            new_user = User(
                user_id=str(datetime.utcnow().timestamp()),  # Generate a unique user ID
                user_name=user_name,
                password=password,  # Store the password as plain text for now
                role=role,
                email=email,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                created_by=current_user,  # Set the logged-in user as the creator
                updated_by=current_user   # Set the logged-in user as the updater
            )

            try:
                db.session.add(new_user)
                db.session.commit()
                flash("User added successfully!", 'success')
                return redirect(url_for('edit_user', user_id=new_user.user_id))  # Redirect to the edit page for the new user
            except Exception as e:
                db.session.rollback()
                flash("Error adding user: " + str(e), 'danger')
                return redirect(url_for('add_user'))  # Stay on the add user page if there's an error

        return render_template('add_user.html')  # Render the add_user template
    else:
        flash("You do not have permission to add a user.", 'danger')
        return redirect(url_for('dashboard'))  # Redirect to the dashboard if permission is not granted



@app.route('/edit_user', methods=['GET', 'POST'])
def edit_user():
    user = None  # Initialize user variable to None, in case no user is found.
    
    if request.method == 'POST':
        # Get the user input from the form (user_id or user_name)
        user_id_or_name = request.form['user_id_or_name']
        
        # Try to find user by user_id first
        user = User.query.filter_by(user_id=user_id_or_name).first()

        # If not found, try to find by user_name
        if not user:
            user = User.query.filter_by(user_name=user_id_or_name).first()

        # If no user is found, show a flash message and stay on the page
        if not user:
            flash("User not found.", 'danger')
            return redirect(url_for('edit_user'))  # Stay on the same page if no user is found

        # Update user information if the form was submitted
        user_name = request.form['username']
        password = request.form['password']
        role = request.form['role']
        email = request.form['email']

        # If a password is entered, update it
        if password:
            user.password = password  # For now, we're storing passwords as plain text

        # Update other fields
        user.user_name = user_name
        user.role = role
        user.email = email
        user.updated_at = datetime.utcnow()

        # Optionally, store the current user (from session) as the one who made the update
        user.updated_by = session.get('user', 'unknown')  # Use session's 'user' for tracking

        try:
            db.session.commit()  # Commit the changes to the database
            flash("User updated successfully!", 'success')
            return redirect(url_for('view_users'))  # After successful update, go to the user list
        except Exception as e:
            db.session.rollback()  # Rollback changes if there's an error
            flash(f"Error updating user: {str(e)}", 'danger')
            return redirect(url_for('edit_user'))  # Stay on the edit page if an error occurs

    return render_template('edit_user.html', user=user)



@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if 'Delete User' in session['permissions'].get('User Management', []):
        user = User.query.get(user_id)  # Fetch user by user_id
        
        # Get the logged-in user's ID (from session or another method)
        logged_in_user_id = session.get('user_id')  # Assuming the user ID is stored in session
        
        # Check if the logged-in user is trying to delete their own account
        if user_id == logged_in_user_id:
            flash("You cannot delete your own account.", 'danger')
            return redirect(url_for('view_users'))  # Redirect to view users page if trying to delete own account
        
        try:
            db.session.delete(user)
            db.session.commit()
            flash("User deleted successfully!", 'success')
            return redirect(url_for('view_users'))
        except Exception as e:
            db.session.rollback()
            flash("Error deleting user: " + str(e), 'danger')
            return redirect(url_for('view_users'))
    else:
        flash("You do not have permission to delete a user.", 'danger')
        return redirect(url_for('dashboard'))





@app.route('/assign_roles', methods=['GET', 'POST'])
def assign_roles():
    if request.method == 'POST':
        user_id = request.form['user_id']
        group_id = request.form['group_id']

        user_group = UserGroup.query.filter_by(user_id=user_id).first()
        if user_group:
            user_group.group_id = group_id
        else:
            new_user_group = UserGroup(user_id=user_id, group_id=group_id, assigned_at=datetime.utcnow())
            db.session.add(new_user_group)

        try:
            db.session.commit()
            flash("Role assigned successfully!", 'success')
            return redirect(url_for('user_management'))
        except Exception as e:
            db.session.rollback()
            flash("Error assigning role: " + str(e), 'danger')
            return redirect(url_for('assign_roles'))

    users = User.query.all()
    groups = UGroup.query.all()
    return render_template('assign_roles.html', users=users, groups=groups)



@app.route('/view_customers')
def view_customers():
    if 'View Customers' in session['permissions'].get('Customer Management', []):
        customers = Customer.query.all()  # Fetch all customers
        return render_template('view_customers.html', customers=customers)
    else:
        flash("You do not have permission to view customers.", 'danger')
        return redirect(url_for('dashboard'))


@app.route('/edit_customer/<customer_id>', methods=['GET', 'POST'])
def edit_customer(customer_id):
    # Fetch the customer using the customer_id
    customer = Customer.query.get(customer_id)
    if not customer:
        flash("Customer not found.", 'danger')
        return redirect(url_for('view_customers'))  # Redirect to view customers if customer is not found
    
    if request.method == 'POST':
        # Update customer details
        customer.first_name = request.form['first_name']
        customer.last_name = request.form['last_name']
        customer.email = request.form['email']
        customer.phone = request.form['phone']
        customer.address = request.form['address']
        customer.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            flash("Customer updated successfully!", 'success')
            return redirect(url_for('view_customers'))  # Redirect to the customer list after successful update
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating customer: {str(e)}", 'danger')
            return redirect(url_for('edit_customer', customer_id=customer_id))  # Stay on the edit page if error occurs

    return render_template('edit_customer.html', customer=customer)


@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    if 'Add Customer' in session['permissions'].get('Customer Management', []):
        if request.method == 'POST':
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            phone = request.form['phone']
            address = request.form['address']

            new_customer = Customer(
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone=phone,
                address=address
            )
            
            try:
                db.session.add(new_customer)
                db.session.commit()
                flash("Customer added successfully!", 'success')
                return redirect(url_for('view_customers'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error adding customer: {str(e)}", 'danger')
                return redirect(url_for('add_customer'))  # Stay on the add customer page if there's an error

        return render_template('add_customer.html')  # Render the add_customer template
    else:
        flash("You do not have permission to add customers.", 'danger')
        return redirect(url_for('dashboard'))  # Redirect to the dashboard if permission is not granted

    
@app.route('/delete_customer/<customer_id>', methods=['POST'])
def delete_customer(customer_id):
    if 'Delete Customer' in session['permissions'].get('Customer Management', []):
        customer = Customer.query.get(customer_id)
        try:
            db.session.delete(customer)
            db.session.commit()
            flash("Customer deleted successfully!", 'success')
            return redirect(url_for('view_customers'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting customer: {str(e)}", 'danger')
            return redirect(url_for('view_customers'))
    else:
        flash("You do not have permission to delete customers.", 'danger')
        return redirect(url_for('dashboard'))


@app.route('/view_sales')
def view_sales():
    if 'View Sales Orders' in session['permissions'].get('Sales Management', []):
        sales = SalesOrder.query.all()  # Fetch all sales
        return render_template('view_sales.html', sales=sales)
    else:
        flash("You do not have permission to view sales.", 'danger')
        return redirect(url_for('dashboard'))


@app.route('/create_sales', methods=['GET', 'POST'])
def create_sales():
    if request.method == 'POST':
        order_id = request.form['order_id']
        customer_id = request.form['customer_id']
        total_amount = request.form['total_amount']

        # Create a new sale
        new_sale = SalesOrder(
            order_id=order_id,
            customer_id=customer_id,
            total_amount=total_amount
        )
        
        try:
            db.session.add(new_sale)
            db.session.commit()
            flash("Sale created successfully!", 'success')
            return redirect(url_for('view_sales'))  # Redirect after creation
        except Exception as e:
            db.session.rollback()
            flash("Error creating sale: " + str(e), 'danger')
            return redirect(url_for('create_sales'))  # Stay on the page if there's an error

    customers = Customer.query.all()  # Get all customers
    sale = None  # Initialize sale to None if it's not being passed
    return render_template('create_sales.html', customers=customers, sale=sale)


@app.route('/edit_sales/<order_id>', methods=['GET', 'POST'])
def edit_sales(order_id):
    if 'Edit Sales Orders' in session['permissions'].get('Sales Management', []):
        sale = SalesOrder.query.get(order_id)
        if not sale:
            flash("Sale not found.", 'danger')
            return redirect(url_for('view_sales'))  # Redirect to sales list if sale is not found

        if request.method == 'POST':
            sale.customer_id = request.form['customer_id']
            sale.total_amount = request.form['total_amount']
            sale.status = request.form['status']
            sale.updated_at = datetime.utcnow()

            try:
                db.session.commit()
                flash("Sale updated successfully!", 'success')
                return redirect(url_for('view_sales'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error updating sale: {str(e)}", 'danger')
                return redirect(url_for('edit_sales', order_id=order_id))  # Stay on the edit page if error occurs

        customers = Customer.query.all()  # Get all customers for the dropdown
        return render_template('edit_sales.html', sale=sale, customers=customers)
    else:
        flash("You do not have permission to edit sales.", 'danger')
        return redirect(url_for('dashboard'))

@app.route('/delete_sales/<order_id>', methods=['POST'])
def delete_sales(order_id):
    if 'Delete Sales Orders' in session['permissions'].get('Sales Management', []):
        sale = SalesOrder.query.get(order_id)
        try:
            db.session.delete(sale)
            db.session.commit()
            flash("Sale deleted successfully!", 'success')
            return redirect(url_for('view_sales'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting sale: {str(e)}", 'danger')
            return redirect(url_for('view_sales'))
    else:
        flash("You do not have permission to delete sales.", 'danger')
        return redirect(url_for('dashboard'))




if __name__ == '__main__':
    app.run(debug=True)

