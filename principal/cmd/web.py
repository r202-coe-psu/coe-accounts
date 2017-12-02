import principal

def main():
    options = principal.get_program_options()
    app = principal.create_app()

    app.run(
        debug=options.debug,
        host=options.host,
        port=int(options.port)
    )
