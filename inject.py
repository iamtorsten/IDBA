import frida


class Inject:
    def __init__(self, target: str):
        self.target = target

    def attach(self):
        device = frida.get_usb_device()
        app = device.get_frontmost_application()
        if app:
            target = app.pid
        else:
            target = self.target
        session = device.attach(target)
        return device, session

    def source(self, session, code):
        return session.create_script(code)