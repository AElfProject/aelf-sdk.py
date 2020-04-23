brew install redis
brew services start redis
brew install unzip
mkdir -p ~/.local/share/aelf/keys
cd ../../
wget https://github.com/AElfProject/AElf/releases/download/v1.0.0-preview1/aelf.zip && unzip aelf.zip
cp scripts/aelf-node/keys/SD6BXDrKT2syNd1WehtPyRo3dPBiXqfGUj8UJym7YP9W9RynM.json  ~/.local/share/aelf/keys/
cp scripts/aelf-node/app* aelf/
echo "start node"
cd aelf && dotnet AElf.Launcher.dll >/dev/null 2>&1 &
