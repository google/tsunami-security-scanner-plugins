GENERATED_PLUGINS_PATH=~/tsunami/plugins/
./gradlew build
cp ./build/libs/*.jar "${GENERATED_PLUGINS_PATH}"
