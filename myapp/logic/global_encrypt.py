from .rsa_cpu import RsaEncryptCpu
from .rsa_gpu import RsaEncryptGpu
from .aes_cpu import AesEncryptCpu
from .aes_gpu import AesEncryptGpu

class ChooseEncrypt():

    def encryption_mode(self, name, mode):
        if name == 'rsa' and mode == 'cpu':
            return RsaEncryptCpu
        elif name == 'rsa' and mode == 'gpu':
            return RsaEncryptGpu
        elif name == 'aes' and mode == 'cpu':
            return AesEncryptCpu
        elif name == 'aes' and mode == 'gpu':
            return AesEncryptGpu
