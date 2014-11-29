debug:
	./gradlew assembleDebug

debug-install:
	adb install -r app/build/outputs/apk/app-debug.apk

uninstall:
	adb uninstall com.ruilopes.scd

release: SecureConnectionDetails.keystore
	./gradlew clean assembleRelease

release-install:
	adb install -r app/build/outputs/apk/app-release.apk

clean:
	./gradlew clean

SecureConnectionDetails.keystore:
	@echo 'creating signing keystore...'
	keytool -genkey -v -keystore SecureConnectionDetails.keystore -alias scd -dname 'CN=scd,O=ruilopes.com' -keyalg RSA -keysize 2048 -validity 10000

retrace:
	cmd /c "retrace app/build/outputs/mapping/release/mapping.txt stacktrace.txt"
