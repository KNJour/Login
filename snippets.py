

@app.route('/login_user', methods=['POST'])
def login_user():
    query = "SELECT * FROM users WHERE email = %(email)s"data = {
        email
    }
    mysql = connectToMySQL("users")
    result = mysql.query_db(query,data)
    if len(result) >0:
        if bycrypt.check_password_hash(result[0]['password'], request.form['password']):
            session['user_id'] = result [0]['id']
            return redirect('/success')
        else:
            flash("Password does not match")
    else:
        flash("Could not Login!")


        from flask import Flask, render_template, request,session,redirect, flash
from mysqlconnection  import connectToMySQL
app = Flask(__name__)
app.secret_key = "Benny Bob wuz heer."
#SHOW
@app.route('/show/<int:dojo_id>')
def show(dojo_id):
    query = "SELECT * FROM ninjas JOIN dojos ON dojos.id = ninjas.dojo_id WHERE dojo_id = %(dojo_id)s;"
    data = {
        "dojo_id": dojo_id
    }
    ninjas = connectToMySQL("dojos_and_ninjas_schema").query_db(query,data)
    print(ninjas)
    return render_template("dojo_show.html", ninjas = ninjas)
#GOES TO CREATE PAGE
@app.route('/create')
def create():
    query = "SELECT * FROM dojos"
    dojos = connectToMySQL("dojos_and_ninjas_schema").query_db(query)
    print(dojos)
    return render_template("ninja.html", dojos = dojos)

#PROCESSES WHATS ON CREATE PAGE
@app.route('/create_ninja', methods=['POST'])
def create_ninja():
    mysql = connectToMySQL("dojos_and_ninjas_schema")
    query = "INSERT INTO ninjas (first_name, last_name, age, created_at, updated_at, dojo_id) VALUES (%(first_name)s,%(last_name)s,%(age)s,NOW(),NOW(),%(dojo_id)s);"

    data = {
        "first_name": request.form["first_name"],
        "last_name": request.form["last_name"],
        "age": request.form["age"],
        "dojo_id": request.form["dojo"]
    }
    new_ninja_id = mysql.query_db(query,data)
    return redirect("/another")

@app.route('/create_dojo', methods=['POST'])
def create_dojo():
    mysql = connectToMySQL("dojos_and_ninjas_schema")
    query = "INSERT INTO dojos (name, created_at, updated_at) VALUES (%(dojo_name)s,NOW(),NOW());"
    print(query)
    data = {
        "dojo_name": request.form['dojo_name']
    }
    new_dojo_id = mysql.query_db(query, data)
    return redirect ("/")

@app.route('/another')
def another():
    return render_template("add_another.html")


@app.route('/')
def dojos():
    query = "SELECT * FROM dojos;"
    dojos = connectToMySQL('dojos_and_ninjas_schema').query_db(query)
    return render_template("dojo.html", all_dojos = dojos)

if __name__=="__main__":
    app.run(debug=True)