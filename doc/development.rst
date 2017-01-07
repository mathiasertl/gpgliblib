###########
Development
###########

To develop your own backend, simply subclass :py:class:`~gpgliblib.base.GpgBackendBase`
and implement these functions:

* :py:func:`~gpgliblib.base.GpgBackendBase.sign`
* :py:func:`~gpgliblib.base.GpgBackendBase.encrypt`
* :py:func:`~gpgliblib.base.GpgBackendBase.sign_encrypt`
* :py:func:`~gpgliblib.base.GpgBackendBase.import_key`
* :py:func:`~gpgliblib.base.GpgBackendBase.import_private_key`
* :py:func:`~gpgliblib.base.GpgBackendBase.expires`

The constructor should take at least the same parameters as GpgBackendBase. If
you provide additional keyword arguments, also be sure to override
:py:func:`~gpgliblib.base.GpgBackendBase.get_settings` to make sure the
:py:class:`~gpgliblib.base.GpgBackendBase.settings` context manager works
correctly. For example::

   class MyBackend(GpgBackendBase):
       def __init__(self, my_setting, **kwargs):
           super(MyBackend, self).__init__(**kwargs)
           self.my_setting = my_setting

       def get_settings(self):
           settings = super(MyBackend, self).get_settings()
           settings['my_setting'] = self.my_setting
           return settings
