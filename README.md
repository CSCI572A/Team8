# Setting up environment

1. Create a virtual environment with Anaconda using
`conda create --name <your_env_name> python=3.10`

2. Install pip with conda
`conda install pip`

3. Install dependencies for the project
`pip install -r requirements.txt`

4. You are all setup

# Installing new dependencies

1. Run
`pip install <dependency_name>`

2. Update requirements.txt with
`pip freeze > requirements.txt`

# Formatting code

1. Run
`black .` for formatting code style

2. Run
`isort .` for formatting sorting style

3. Run
`pydocstyle` for formatting code documentation

# Unit testing code

1. Run `pytest .`