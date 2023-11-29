# cuda_context.py

import pycuda.driver as drv

class CudaContext:
    initialized = False
    context = None

    @classmethod
    def initialize(cls):
        if not cls.initialized:
            drv.init()
            device = drv.Device(0)  # Asume que usas el primer dispositivo GPU
            cls.context = device.make_context()
            cls.initialized = True

    @classmethod
    def get_context(cls):
        if not cls.initialized:
            cls.initialize()
        return cls.context

    @classmethod
    def pop_context(cls):
        if cls.initialized and cls.context:
            cls.context.pop()
            cls.initialized = False
