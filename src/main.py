from libs.winapp import WinApp


if __name__ == "__main__":
    try:
        winapp = WinApp()
        winapp.run()
    except KeyboardInterrupt:
        winapp.close()